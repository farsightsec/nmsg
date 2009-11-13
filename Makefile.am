#SUBDIRS = nmsg src examples doc
SUBDIRS =
AM_CFLAGS = @EXTRA_CFLAGS@

EXTRA_DIST = \
	wreck/LICENSE \
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

if INTERNAL_WDNS
SUBDIRS += wreck/wdns/msg
endif

SUBDIRS += nmsg src doc
