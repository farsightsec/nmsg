DESTDIR ?= /
PREFIX ?= /usr/local

CYTHON_SRC_FILES = \
	_nmsg.pyx \
	nmsg.pxi \
	nmsg_input.pyx \
	nmsg_io.pyx \
	nmsg_message.pyx \
	nmsg_msgmod.pyx \
	nmsg_msgtype.pyx \
	nmsg_output.pyx \
	nmsg_util.pyx

_nmsg.so: $(CYTHON_SRC_FILES)
	python setup.py build

clean:
	python setup.py clean
	rm -f _nmsg.so
	rm -rf build

install:
	python setup.py install --root=$(DESTDIR) --prefix=$(PREFIX)
