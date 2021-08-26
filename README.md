[![Build Status](https://travis-ci.org/farsightsec/nmsg.png?branch=master)](https://travis-ci.org/farsightsec/nmsg)

Farsight nmsg
=============

Building and installing nmsg
----------------------------

nmsg has the following external dependencies:

* [pcap](http://www.tcpdump.org/)

* [protobuf](https://github.com/protocolbuffers/protobuf)

* [protobuf-c](https://github.com/protobuf-c/protobuf-c), version 1.0.1 or
  higher. Previous versions WILL NOT WORK.

* [wdns](https://github.com/farsightsec/wdns)

* [zmq](http://zeromq.org/)

* [yajl](http://lloyd.github.io/yajl/)

* [zlib](http://www.zlib.net/)

On Debian systems, the following packages should be installed, if available:

    pkg-config libpcap0.8-dev libprotobuf-c-dev protobuf-c-compiler libzmq3-dev libyajl-dev zlib1g-dev

Note that on Debian systems, binary packages of nmsg and its dependencies are
available from
[a Debian package repository maintained by Farsight Security](https://www.farsightsecurity.com/solutions/security-information-exchange/sie-debian/).
These packages should be used in preference to building from source on
Debian-based systems.

On FreeBSD systems, the following ports should be installed, if available:

    devel/libzmq
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

Support for `libzmq` can be disabled by passing the `--without-libzmq` parameter
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

Building external modules
-------------------------

`nmsg` can be extended at runtime with new message types by installing message
modules into the `libnmsg` module directory, which defaults to
`$libdir/nmsg`. This location is configurable by passing the
`--with-pluginsdir` parameter to the `configure` script.

Message module plugins are `.so` files which export either a symbol named
`nmsg_msgmod_ctx` or a symbol named `nmsg_msgmod_ctx_array`. If
`nmsg_msgmod_ctx` is exported, it is an object of type `struct
nmsg_msgmod_plugin`. Otherwise, if `nmsg_msgmod_ctx_array` is exported, it is a
`NULL`-terminated array of pointers to `struct nmsg_msgmod_plugin`'s. See
[nmsg/msgmod_plugin.h](nmsg/msgmod_plugin.h) for details about developing
plugins using the message module plugin interface.

`nmsg` as of version 0.11.0 supports filter modules, which can be loaded by
`nmsgtool` or the `nmsg_io_add_filter_module()` API call. Filter module plugins
are `.so` files which export a symbol named `nmsg_fltmod_plugin_export`. See
[nmsg/fltmod_plugin.h](nmsg/fltmod_plugin.h) for details about developing
plugins using the filter module plugin interface.

`nmsg` itself ships with a message module and a filter module. See the `Message
modules` and `Filter modules` sections in [Makefile.am](Makefile.am) for
examples of using Automake to build `nmsg` modules. Also see
[sie-nmsg](https://github.com/farsightsec/sie-nmsg) for an example of an
external message module, and for general information on building plugins using
Autotools see the [Autotools
Mythbuster](https://autotools.io/libtool/plugins.html) documentation.

Examples
--------

C language examples are in the `examples/` directory.
