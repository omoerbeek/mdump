# $Id: Makefile 2066 2011-10-26 15:40:28Z jkoshy $

PROG=	mdump
SRCS=	mdump.c addr2line.c

BINDIR=	/usr/local/bin
MANDIR=/usr/local/man/man

CPPFLAGS+= -I /usr/local/include/elftoolchain
CFLAGS+= -Wall -g

LDFLAGS+= -L /usr/local/lib/elftoolchain
LDADD=	-lelftc -ldwarf -lelf

.include <bsd.prog.mk>
