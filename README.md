[![Build Status](https://travis-ci.org/farsightsec/nmsg.png?branch=master)](https://travis-ci.org/farsightsec/nmsg)

Farsight nmsg
=============

Contact information
-------------------

Questions about `libnmsg`, `nmsgtool`, `pynmsg`, the development of `libnmsg`
client programs or language bindings, or the `NMSG` binary protocol should be
directed to the `nmsg-dev` mailing list:

https://lists.farsightsecurity.com/mailman/listinfo/nmsg-dev

Building and installing nmsg
----------------------------

nmsg has the following external dependencies:

* [pcap](http://www.tcpdump.org/)

* [protobuf](https://code.google.com/p/protobuf/)

* [protobuf-c](https://github.com/protobuf-c/protobuf-c), version 1.0.1 or
  higher. Previous versions WILL NOT WORK.

* [wdns](https://github.com/farsightsec/wdns)

* [libxs](http://www.crossroads.io/)

* [yajl](http://lloyd.github.io/yajl/)

* [zlib](http://www.zlib.net/)

On Debian systems, the following packages should be installed, if available:

    pkg-config libpcap0.8-dev libprotobuf-c-dev protobuf-c-compiler libxs-dev libyajl-dev zlib1g-dev

Note that on Debian systems, binary packages of nmsg and its dependencies are
available from
[a Debian package repository maintained by Farsight Security](https://archive.farsightsecurity.com/SIE_Software_Installation_Debian/).
These packages should be used in preference to building from source on
Debian-based systems.

On FreeBSD systems, the following ports should be installed, if available:

    devel/libxs
    devel/yajl
    devel/pkgconf
    devel/protobuf
    devel/protobuf-c

Note that nmsg >= 0.9.0 has been designed to use the 1.x release series of
protobuf-c, while previous releases of nmsg were designed to use the 0.x release
series of protobuf-c. Make sure you have the correct version of protobuf-c
installed before attempting to build nmsg.

After satisfying the prerequisites, `./configure && make && make install` should
compile and install `libnmsg` and `nmsgtool` to `/usr/local`. If building from a
git checkout, run the `./autogen.sh` command first to generate the `configure`
script.

Support for `libxs` can be disabled by passing the `--without-libxs` parameter
to the `configure` script.

Support for `yajl` can be disabled by passing the `--without-yajl` parameter
to the `configure` script.

The documentation for the `libnmsg` API is located in the `doc/doxygen/html`
directory. To rebuild the API documentation, run `make html`. This requires
Doxygen to be installed.

The manpage documentation is built using DocBook 5, DocBook XSL, and xsltproc.
git checkouts do not include the built manpages, but tarball releases do. To
build the documentation on Debian systems, the following packages should be
installed:

    docbook5-xml docbook-xsl-ns xsltproc

Building external message modules
---------------------------------

`libnmsg` can be extended at runtime with new message types by installing
message modules into the `libnmsg` module directory, which defaults to
`$PREFIX/lib/nmsg`. This location is configurable by passing the
`--with-plugindir` parameter to the `configure` script.

Examples
--------

C language examples are in the `examples/` directory.
