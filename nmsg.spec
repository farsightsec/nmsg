Name:           nmsg
Version:        0.15.1
Release:        1%{?dist}
Summary:	network message encapsulation library

License:        Apache-2.0
URL:            https://github.com/farsightsec/nmsg
Source0:        https://dl.farsightsecurity.com/dist/nmsg/%{name}-%{version}.tar.gz

BuildRequires:  libpcap-devel protobuf-c-devel wdns-devel yajl-devel >= 2.1.0 zlib-devel
#BuildRequires:  zlib-devel

%description

%package -n libnmsg
Summary:	network message encapsulation library
Requires:	libpcap protobuf-c zlib
# yajl

%description -n libnmsg
The NMSG format is an efficient encoding of typed, structured data into
payloads which are packed into containers which can be transmitted over
the network or stored to disk.

This package contains the shared library for libnmsg.

%package -n nmsgtool
Summary:	network message encapsulation tool
Requires:	libnmsg%{?_isa} = %{version}-%{release}, libpcap

%description -n nmsgtool
nmsgtool provides a command-line interface to control the transmission,
storage, creation, and conversion of NMSG payloads.

%package -n libnmsg-devel
Summary:	network message encapsulation library (development files)
Requires:	libnmsg%{?_isa} = %{version}-%{release}, protobuf-c-devel

%description -n libnmsg-devel
libnmsg is the reference implementation of the NMSG format and provides
an extensible interface for creating and parsing messages in NMSG format.

This package contains the static library, headers, and development
documentation for libnmsg.

%package flt1-module-sample
Summary:	sample filter module plugin for libnmsg

%description flt1-module-sample
This package contains the libnmsg 'sample' filter module plugin which
extends the libnmsg runtime to support sampling of the message stream.
It can perform either systematic count-based sampling or uniform
probabilistic sampling.

%package msg9-module-base
Summary:	base message module plugin for libnmsg
Requires:	libpcap protobuf-c wdns

%description msg9-module-base
This package extends the libnmsg runtime to support the following
message types: base/dns, base/dnsqr, base/email, base/encode, base/http,
base/ipconn, base/linkpair, base/logline, base/ncap, base/packet,
base/pkt, and base/xml.

%prep
%setup -q

%build
[ -x configure ] || autoreconf -fvi
# TODO: RPM package libxs-devel
%configure --without-libxs
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%make_install

%files -n libnmsg
%defattr(-,root,root,-)
%{_libdir}/*.so.*
%exclude %{_libdir}/libnmsg.la

%files -n libnmsg-devel
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/pkgconfig/*
%{_includedir}/*

# TODO: development docs

%files -n nmsgtool
%_bindir/*
%_mandir/man1/*

%files flt1-module-sample
%{_libdir}/nmsg/nmsg_flt1_sample.so
%exclude %{_libdir}/nmsg/nmsg_flt1_sample.la

%files msg9-module-base
%{_libdir}/nmsg/nmsg_msg9_base.so
%exclude %{_libdir}/nmsg/nmsg_msg9_base.la
%exclude %{_prefix}/share/nmsg/base/*.proto

%doc

%changelog
