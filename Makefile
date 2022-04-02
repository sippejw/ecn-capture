# Makefile, modified from PF_RING examples Makefile.in

#
# PF_RING
#
PFRINGDIR  = ./PF_RING/userland/lib
LIBPFRING  = ${PFRINGDIR}/libpfring.a

#
# PF_RING aware libpcap
#
PCAPDIR    = ./PF_RING/userland/libpcap
LIBPCAP    = ${PCAPDIR}/libpcap.a

PFUTILSDIR = ./PF_RING/userland/examples

#
# Search directories
#
PFRING_KERNEL= ./PF_RING/kernel/
INCLUDE    = -I${PFRING_KERNEL} -I${PFRING_KERNEL}/plugins -I${PFRINGDIR} -I${PFUTILSDIR} -I${PCAPDIR} -Ithird-party -I`${PFRINGDIR}/pfring_config --include`

#
# C compiler and flags
#
CC         = gcc
CFLAGS     =  -O2 -DHAVE_PF_RING -Wall ${INCLUDE} -DENABLE_BPF -D HAVE_PF_RING_ZC # -g
#CFLAGS     += -g

#
# User and System libraries
#
DEBUG_OR_RELEASE = release
LIBS       =  ${LIBPFRING} ${LIBPCAP} `${PFRINGDIR}/pfring_config --libs` -lrt -Ltarget/${DEBUG_OR_RELEASE} -lecn_capture -ldl -lm -L/usr/local/lib -lssl -lcrypto -lpthread

all: ecn-capture

ecn-capture.o: main.c #${PFUTILSDIR}/pfutils.c
	${CC} ${CFLAGS} -c $< -o $@

rust-code:
	cargo build --${DEBUG_OR_RELEASE}

ecn-capture: ecn-capture.o ${LIBPFRING} rust-code
		${CC} ${CFLAGS} $< -o $@ ${LIBS}

clean:
	@rm -f ecn-capture *.o *~