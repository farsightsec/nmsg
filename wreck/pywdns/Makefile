DESTDIR ?= /
PREFIX ?= /usr/local

wdns.so: wdns.pxi wdns.pyx
	touch wdns.pyx
	python setup.py build_ext --inplace

clean:
	python setup.py clean
	rm -f wdns.so

install:
	python setup.py install --root=$(DESTDIR) --prefix=$(PREFIX)
