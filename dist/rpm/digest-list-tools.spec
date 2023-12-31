name:           digest-list-tools
Version:        0.3.95
Release:        2
Summary:        Utilities for IMA Digest Lists extension

Source0:        https://gitee.com/openeuler/%{name}/repository/archive/v%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
License:        GPLv2
Url:            https://gitee.com/openeuler/digest-list-tools

BuildRequires:  autoconf automake libcurl-devel libtool rpm-devel dracut gzip
BuildRequires:  libcap-devel libcmocka-devel libselinux-devel

%if 0%{?suse_version}
BuildRequires:  libopenssl-devel glibc-devel-static
BuildRequires:  linux-glibc-devel keyutils-devel
%else
BuildRequires:  openssl-devel kernel-headers
BuildRequires:  keyutils-libs-devel glibc-static
%endif

%description
This package includes the tools for configure the IMA Digest Lists extension.

%package devel
Summary:        The devel package for %{name}
Requires:       %{name} = %{version}-%{release}
Provides:       %{name}-static = %{version}-%{release}
Provides:       %{name}-headers = %{version}-%{release}

%description devel
The %{name}-devel package contains the header files necessary for developing
related programs.

%prep
%autosetup -n %{name}-%{version} -p1

%build
autoreconf -iv
%configure
make %{?_smp_mflags}
make check

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists.tlv
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists.sig
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man1

%post
ldconfig

%postun
ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %{_sysconfdir}/dracut.conf.d
%{_sysconfdir}/dracut.conf.d/digestlist.conf
%dir %{_sysconfdir}/ima
%dir %{_sysconfdir}/ima/digest_lists
%dir %{_sysconfdir}/ima/digest_lists.tlv
%dir %{_sysconfdir}/ima/digest_lists.sig
%{_bindir}/gen_digest_lists
%{_bindir}/setup_ima_digest_lists
%{_bindir}/setup_ima_digest_lists_demo
%{_bindir}/setup_grub2
%{_bindir}/manage_digest_lists
%{_bindir}/upload_digest_lists
%{_bindir}/verify_digest_lists
%{_bindir}/write_rpm_pgp_sig
%{_libexecdir}/rpm_parser
%{_libdir}/libdigestlist-base.so
%dir %{_libdir}/digestlist
%{_libdir}/digestlist/libgenerator-compact.so
%{_libdir}/digestlist/libgenerator-copy.so
%{_libdir}/digestlist/libgenerator-rpm.so
%{_libdir}/digestlist/libgenerator-unknown.so
%{_libdir}/digestlist/libparser-compact_tlv.so
%{_libdir}/digestlist/libparser-rpm.so
%{_unitdir}/setup-ima-digest-lists.service
%dir /usr/lib/dracut/modules.d/98digestlist
%{_prefix}/lib/dracut/modules.d/98digestlist/module-setup.sh
%{_prefix}/lib/dracut/modules.d/98digestlist/upload_meta_digest_lists.sh
%{_prefix}/lib/dracut/modules.d/98digestlist/load_digest_lists.sh

%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/digestlist
%{_includedir}/digestlist/*.h
%exclude /usr/lib64/digestlist/*.a
%exclude /usr/lib64/digestlist/*.la
%exclude /usr/lib64/libdigestlist-base.a
%exclude /usr/lib64/libdigestlist-base.la

%doc
%dir /usr/share/digest-list-tools
%{_datarootdir}/digest-list-tools/README.md
%{_datarootdir}/digest-list-tools/gen_digest_lists.txt
%{_datarootdir}/digest-list-tools/setup_ima_digest_lists.txt
%{_datarootdir}/digest-list-tools/setup_ima_digest_lists_demo.txt
%{_datarootdir}/digest-list-tools/manage_digest_lists.txt
%{_datarootdir}/digest-list-tools/upload_digest_lists.txt
%{_datarootdir}/digest-list-tools/verify_digest_lists.txt
%{_datarootdir}/digest-list-tools/write_rpm_pgp_sig.txt
%{_mandir}/man1/gen_digest_lists.1.gz
%{_mandir}/man1/setup_ima_digest_lists.1.gz
%{_mandir}/man1/setup_ima_digest_lists_demo.1.gz
%{_mandir}/man1/verify_digest_lists.1.gz
%{_mandir}/man1/manage_digest_lists.1.gz
%{_mandir}/man1/upload_digest_lists.1.gz
%{_mandir}/man1/write_rpm_pgp_sig.1.gz
%{_mandir}/man1/%{name}.1.gz

%changelog
* Tue Apr 6 2021 Anakin Zhang <benjamin93@163.com> - 0.3.95-2
- add devel package for digest-list-tools

* Tue Feb 16 2021 Roberto Sassu <roberto.sassu@huawei.com> - 0.3.95-1
- Add support for PGP keys
- Add setup_grub2 script
- Bug fixes

* Mon Sep 14 2020 Anakin Zhang <benjamin93@163.com> - 0.3.94-3
- fix Source0 and Summary in spec

* Thu Sep 10 2020 Anakin Zhang <benjamin93@163.com> - 0.3.94-2
- fix invalid format in i686

* Thu Sep 03 2020 Roberto Sassu <roberto.sassu@huawei.com> - 0.3.94-1
- Add obj_label attribute in file list
- Replace hard coded permission
- Set user.digest_list xattr
- Bug fixes

* Tue Sep 1 2020 Anakin Zhang <benjamin93@163.com> - 0.3.93-3
- set user.digest_list in repair-meta-digest-lists

* Mon Aug 31 2020 Anakin Zhang <benjamin93@163.com> - 0.3.93-2
- remove README file

* Tue Jul 14 2020 Roberto Sassu <roberto.sassu@huawei.com> - 0.3.93-1
- Add support for PGP signatures
- Add support for user space parsers
- Bug fixes

* Thu Jul 02 2020 Roberto Sassu <roberto.sassu@huawei.com> - 0.3.92
- Bug fixes
- Change format of file list for compact/unknown generators

* Wed Jun 03 2020 Roberto Sassu <roberto.sassu@huawei.com> - 0.3.91
- Bug fixes

* Fri Apr 17 2020 Roberto Sassu <roberto.sassu@huawei.com> - 0.3.90
- TLV compact list
- unknown generator
- digest list of metadata

* Tue Mar 19 2019 Roberto Sassu <roberto.sassu@huawei.com> - 0.3
- refactored code
- tests

* Thu Apr 05 2018 Roberto Sassu <roberto.sassu@huawei.com> - 0.2
- PGP signatures
- Multiple digest algorithms
- User space digest list parser
- DEB package format

* Wed Nov 15 2017 Roberto Sassu <roberto.sassu@huawei.com> - 0.1
- Initial version
