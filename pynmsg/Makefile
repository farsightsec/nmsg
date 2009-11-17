DESTDIR ?= /
PREFIX ?= /usr/local

nmsg.so: nmsg_input.pyx nmsg_io.pyx nmsg_message.pyx nmsg_msgmod.pyx nmsg_msgtype.pyx nmsg_output.pyx nmsg_util.pyx nmsg.pxi
	touch nmsg.pyx
	python setup.py build_ext --inplace

clean:
	python setup.py clean
	rm -f nmsg.so

install:
	python setup.py install --root=$(DESTDIR) --prefix=$(PREFIX)
