DESTDIR ?= /
PREFIX ?= /usr/local

wdns.so: wdns.pxi wdns.pyx wdns.c
	touch wdns.pyx
	python setup.py build_ext --inplace

wdns.c: wdns.pyx
	cython wdns.pyx

clean:
	python setup.py clean
	rm -f wdns.so
	rm -rf build

install:
	python setup.py install --root=$(DESTDIR) --prefix=$(PREFIX)
