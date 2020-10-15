/*	$OpenBSD: kdump.c,v 1.143 2020/04/05 08:32:14 mpi Exp $	*/

/*-
 * Copyright (c) 2020 Otto Moerbeek <otto@drijf.net>
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>	/* MAXCOMLEN nitems */
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ktrace.h>
#include <sys/ioctl.h>
#include <sys/tree.h>

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

enum {
	TIMESTAMP_NONE,
	TIMESTAMP_ABSOLUTE,
	TIMESTAMP_RELATIVE,
	TIMESTAMP_ELAPSED
} timestamp = TIMESTAMP_NONE;

int decimal, iohex, fancy = 1;
int needtid, tail, basecol, dump;
char *tracefile = "ktrace.out";
char *malloc_aout = "a.out";
struct ktr_header ktr_header;
pid_t pid_opt = -1;

static int fread_tail(void *, size_t, size_t);

static void ktruser(struct ktr_user *, size_t);
static void usage(void);
static void *xmalloc(size_t);

static int screenwidth;

int
main(int argc, char *argv[])
{
	int ch, silent;
	size_t ktrlen, size;
	int trpoints = KTRFAC_USER;
	const char *errstr;
	void *m;

	if (screenwidth == 0) {
		struct winsize ws;

		if (fancy && ioctl(fileno(stderr), TIOCGWINSZ, &ws) != -1 &&
		    ws.ws_col > 8)
			screenwidth = ws.ws_col;
		else
			screenwidth = 80;
	}

	while ((ch = getopt(argc, argv, "e:f:dDHlnp:RTxX")) != -1)
		switch (ch) {
		case 'e':
			malloc_aout = optarg;
			break;
		case 'f':
			tracefile = optarg;
			break;
		case 'd':
			decimal = 1;
			break;
		case 'D':
			dump = 1; 
			break;
		case 'H':
			needtid = 1;
			break;
		case 'l':
			tail = 1;
			break;
		case 'n':
			fancy = 0;
			break;
		case 'p':
			pid_opt = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr)
				errx(1, "-p %s: %s", optarg, errstr);
			break;
		case 'R':	/* relative timestamp */
			if (timestamp == TIMESTAMP_ABSOLUTE)
				timestamp = TIMESTAMP_ELAPSED;
			else
				timestamp = TIMESTAMP_RELATIVE;
			break;
		case 'T':
			if (timestamp == TIMESTAMP_RELATIVE)
				timestamp = TIMESTAMP_ELAPSED;
			else
				timestamp = TIMESTAMP_ABSOLUTE;
			break;
		case 'x':
			iohex = 1;
			break;
		case 'X':
			iohex = 2;
			break;
		default:
			usage();
		}
	if (argc > optind)
		usage();

	if (pledge("stdio rpath getpw", NULL) == -1)
		err(1, "pledge");

	m = xmalloc(size = 1025);
	if (strcmp(tracefile, "-") != 0)
		if (!freopen(tracefile, "r", stdin))
			err(1, "%s", tracefile);

	if (fread_tail(&ktr_header, sizeof(struct ktr_header), 1) == 0 ||
	    ktr_header.ktr_type != htobe32(KTR_START))
		errx(1, "%s: not a dump", tracefile);
	while (fread_tail(&ktr_header, sizeof(struct ktr_header), 1)) {
		silent = 0;
		if (pid_opt != -1 && pid_opt != ktr_header.ktr_pid)
			silent = 1;
		if (silent == 0) {
			static pid_t pid;
			if (pid)  {
				if (pid != ktr_header.ktr_pid)
					errx(1, "-M and multiple pids seen, "
					    "select one using -p");
			} else
				pid = ktr_header.ktr_pid;
		}

		ktrlen = ktr_header.ktr_len;
		if (ktrlen > size) {
			void *newm;

			if (ktrlen == SIZE_MAX)
				errx(1, "data too long");
			newm = realloc(m, ktrlen+1);
			if (newm == NULL)
				err(1, "realloc");
			m = newm;
			size = ktrlen;
		}
		if (ktrlen && fread_tail(m, ktrlen, 1) == 0)
			errx(1, "data too short");
		if (silent)
			continue;
		if ((trpoints & (1<<ktr_header.ktr_type)) == 0)
			continue;
		switch (ktr_header.ktr_type) {
		case KTR_USER:
			ktruser(m, ktrlen);
			break;
		default:
			printf("\n");
			break;
		}
		if (tail)
			(void)fflush(stdout);
	}
	exit(0);
}

static int
fread_tail(void *buf, size_t size, size_t num)
{
	int i;

	while ((i = fread(buf, size, num, stdin)) == 0 && tail) {
		(void)sleep(1);
		clearerr(stdin);
	}
	return (i);
}

/*
 * Base Formatters
 */

void
showbufc(int col, unsigned char *dp, size_t datalen, int flags)
{
	int width;
	unsigned char visbuf[5], *cp;

	flags |= VIS_CSTYLE;
	putchar('"');
	col++;
	for (; datalen > 0; datalen--, dp++) {
		(void)vis(visbuf, *dp, flags, *(dp+1));
		cp = visbuf;

		/*
		 * Keep track of printables and
		 * space chars (like fold(1)).
		 */
		if (col == 0) {
			(void)putchar('\t');
			col = 8;
		}
		switch (*cp) {
		case '\n':
			col = 0;
			(void)putchar('\n');
			continue;
		case '\t':
			width = 8 - (col&07);
			break;
		default:
			width = strlen(cp);
		}
		if (col + width > (screenwidth-2)) {
			(void)printf("\\\n\t");
			col = 8;
		}
		col += width;
		do {
			(void)putchar(*cp++);
		} while (*cp);
	}
	if (col == 0)
		(void)printf("       ");
	(void)printf("\"\n");
}

struct stackframe {
	void *caller;
	void *object;
};

#define NUM_FRAMES	4
struct malloc_utrace {
	struct stackframe backtrace[NUM_FRAMES];
	size_t sum;
	size_t count;
};

struct malloc_object {
	void *object;
	char name[0];
};

struct objectnode {
	RBT_ENTRY(objectnode) entry;
	struct malloc_object *o;
};


static int
objectcmp(const struct objectnode *e1, const struct objectnode *e2)
{
	return e1->o->object < e2->o->object ? -1 :
	    e1->o->object > e2->o->object;
}

RBT_HEAD(objectshead, objectnode) objects = RBT_INITIALIZER(&objectnode);
RBT_PROTOTYPE(objectshead, objectnode, entry, objectcmp)
RBT_GENERATE(objectshead, objectnode, entry, objectcmp);

void addr2line(const char *object, uintptr_t addr, char **name);

static void
ktruser(struct ktr_user *usr, size_t len)
{
	if (len < sizeof(struct ktr_user))
		errx(1, "invalid ktr user length %zu", len);
	len -= sizeof(struct ktr_user);

	if (dump == 1) {
		if (strcmp(usr->ktr_id, "mallocdumpline") == 0)
			printf("%.*s", (int)len, (unsigned char *)(usr + 1));
		return;
	}

	if (strcmp(usr->ktr_id, "mallocdumpline") == 0)
		return;

	if (strcmp(usr->ktr_id, "mallocleakrecord") == 0 &&
	    len == sizeof(struct malloc_utrace)) {
		struct malloc_utrace u;
		int i;

		memcpy(&u, usr + 1, sizeof(u));
		printf("Leak sum=%zu count=%zu avg=%zu\n", u.sum, u.count,
		    u.sum / u.count);
		for (i = 0; i < NUM_FRAMES; i++) {
			if (u.backtrace[i].caller) {
				struct objectnode key, *obj;
				char *name;
				char *function;

				key.o = xmalloc(sizeof(struct objectnode));
				key.o->object = u.backtrace[i].object;
				obj = RBT_FIND(objectshead, &objects, &key);
				name = (obj != NULL && obj->o != NULL &&
				    obj->o->name[0] != '\0') ? obj->o->name :
				    malloc_aout;
				addr2line(name, (uintptr_t)u.backtrace[i].
				    caller, &function);
				printf(" %s", function);
				free(key.o);
				free(function);
			} else
				break;
		}
		printf("\n");
		return;
	}

	if (strcmp(usr->ktr_id, "mallocobjectrecord") == 0 &&
	    len > sizeof(struct malloc_object) &&
	    len <= sizeof(struct malloc_object) + PATH_MAX) {
		union {
			struct malloc_object m;
			char data[sizeof(struct malloc_object) + PATH_MAX];
		} u;
		struct objectnode *p;

		memcpy(&u, usr + 1, len);
		/* it should be, better make sure p->name is NUL terminated */
		u.data[len - 1] = '\0';
		if (strlen(u.m.name) + 1 != len - sizeof(struct malloc_object))
			errx(1, "internal error");
		p = xmalloc(sizeof(struct objectnode));
		p->o = xmalloc(len);
		p->o->object = u.m.object;
		strlcpy(p->o->name, u.m.name,
		    len - sizeof(struct malloc_object));
		RBT_INSERT(objectshead, &objects, p);
		return;
	}

	printf("unknown malloc record %*.s %zu\n", KTR_USER_MAXIDLEN,
	    usr->ktr_id, len);
}

static void
usage(void)
{

	extern char *__progname;
	fprintf(stderr, "usage: %s "
	    "[-dHDlnRTXx] [-e file] [-f file] [-p pid]\n",
	    __progname);
	exit(1);
}

static void *
xmalloc(size_t sz)
{
	void *p = malloc(sz);

	if (p == NULL)
		err(1, NULL);
	return p;
}

