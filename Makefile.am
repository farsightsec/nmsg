SUBDIRS =
AM_CFLAGS = @EXTRA_CFLAGS@

EXTRA_DIST = \
	COPYRIGHT \
	README \
	tests \
	doc/doxygen/html

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
