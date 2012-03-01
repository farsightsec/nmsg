SUBDIRS =
AM_CFLAGS = @EXTRA_CFLAGS@

EXTRA_DIST = \
	COPYRIGHT \
	README \
	tests \
	wreck/LICENSE \
	doc/doxygen/html \
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
	ustr/LICENSE* \
	ustr/*.[ch]

if INTERNAL_LIBPROTOBUF_C
SUBDIRS += protobuf-c/google/protobuf-c
endif

SUBDIRS += nmsg src doc examples

dep:
	cd nmsg && $(MAKE) $(AM_MAKEFLAGS) protobuf
	cd nmsg/isc && $(MAKE) $(AM_MAKEFLAGS) protobuf

doc/doxygen/html:
	$(MAKE) -C doc/doxygen html

.PHONY: dep
