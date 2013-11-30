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

* [protobuf-c](https://github.com/protobuf-c/protobuf-c)

* [wdns](https://github.com/farsightsec/wdns)

* [libxs](http://www.crossroads.io/)

* [zlib](http://www.zlib.net/)

On Debian systems, the following packages should be installed, if available:

    pkg-config libpcap0.8-dev libprotobuf-c0-dev protobuf-c-compiler libxs-dev zlib1g-dev

On FreeBSD systems, the following ports should be installed, if available:

    devel/libxs
    devel/pkgconf
    devel/protobuf
    devel/protobuf-c

After satisfying the prerequisites, `./configure && make && make install` should
compile and install `libnmsg` and `nmsgtool` to `/usr/local`. If building from a
git checkout, run the `./autogen.sh` command first to generate the `configure`
script.

Support for `libxs` can be disabled by passing the `--without-libxs` parameter
to the `configure` script.

The documentation for the `libnmsg` API is located in the `doc/doxygen/html`
directory. To rebuild the API documentation, run `make html`. This requires
Doxygen to be installed.

Building external message modules
---------------------------------

`libnmsg` can be extended at runtime with new message types by installing
message modules into the `libnmsg` module directory, which defaults to
`$PREFIX/lib/nmsg`. This location is configurable by passing the
`--with-plugindir` parameter to the `configure` script.

Examples
--------

C language examples are in the `examples/` directory.
