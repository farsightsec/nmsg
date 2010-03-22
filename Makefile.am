SUBDIRS =
AM_CFLAGS = @EXTRA_CFLAGS@

EXTRA_DIST = \
	wreck/LICENSE \
	pynmsg/examples/*.py \
	pynmsg/Makefile \
	pynmsg/_nmsg.c \
	pynmsg/_nmsg.pyx \
	pynmsg/nmsg.pxi \
	pynmsg/nmsg.py \
	pynmsg/nmsg_input.pyx \
	pynmsg/nmsg_io.pyx \
	pynmsg/nmsg_message.pyx \
	pynmsg/nmsg_msgmod.pyx \
	pynmsg/nmsg_msgtype.pyx \
	pynmsg/nmsg_output.pyx \
	pynmsg/nmsg_util.pyx \
	pynmsg/setup.py \
	ustr/*.[ch]

if INTERNAL_LIBPROTOBUF_C
SUBDIRS += protobuf-c/google/protobuf-c
endif

if INTERNAL_LIBUSTR
SUBDIRS += ustr
endif

if INTERNAL_LIBWDNS
SUBDIRS += wreck/wdns/msg
endif

SUBDIRS += nmsg src doc examples

dep:
	cd nmsg && $(MAKE) $(AM_MAKEFLAGS) protobuf
	cd nmsg/isc && $(MAKE) $(AM_MAKEFLAGS) protobuf
	cd pynmsg && $(MAKE) nmsg.c

.PHONY: dep
