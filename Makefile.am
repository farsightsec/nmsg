#SUBDIRS = nmsg src examples doc
SUBDIRS = nmsg src doc

AM_CFLAGS = @EXTRA_CFLAGS@

EXTRA_DIST = \
	pynmsg/examples/*.py \
	pynmsg/nmsg.c \
	pynmsg/nmsg.pxi \
	pynmsg/nmsg.pyx \
	pynmsg/nmsg_input.pyx \
	pynmsg/nmsg_io.pyx \
	pynmsg/nmsg_message.pyx \
	pynmsg/nmsg_msgmod.pyx \
	pynmsg/nmsg_msgtype.pyx \
	pynmsg/nmsg_output.pyx \
	pynmsg/setup.py

if INTERNAL_PROTOBUF_C
SUBDIRS += protobuf-c/google/protobuf-c
endif
