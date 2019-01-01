%define contentdir /var/www

Summary:	Squid proxy log analyzer and report generator
Name:		squidanalyzer
Version:	6.6
Release:	1%{?dist}
License:	GPLv3+
Group:		Monitoring
URL:		http://squidanalyzer.darold.net/
Source:		http://prdownloads.sourceforge.net/squid-report/%{name}-%{version}.tar.gz
BuildRequires:	perl
BuildArch:	noarch

BuildRequires: perl-ExtUtils-MakeMaker, perl-ExtUtils-Install, perl-ExtUtils-Manifest, perl-ExtUtils-ParseXS, perl-Time-HiRes
BuildRequires: gdbm-devel, libdb-devel, perl-devel, systemtap-sdt-devel

%description
Squid proxy native log analyzer and reports generator with full
statistics about times, hits, bytes, users, networks, top URLs and
top domains. Statistic reports are oriented toward user and
bandwidth control; this is not a pure cache statistics generator.

SquidAnalyzer uses flat files to store data and doesn't need any SQL,
SQL Lite or Berkeley databases.

This log analyzer is incremental and should be run in a daily cron,
or more often with heavy proxy usage.

%prep

%setup -q

%build
%{__perl} Makefile.PL DESTDIR=%{buildroot} LOGFILE=%{_logdir}/squid/access.log BINDIR=%{_bindir} HTMLDIR=%{contentdir}/%{name} BASEURL=/%{name} MANDIR=%{_mandir}/man3 QUIET=yes

make

%install
%{__rm} -rf %{buildroot}

%{__make} install DESTDIR=%{buildroot}
install etc/* %{buildroot}%{_sysconfdir}/%{name}/
install -d %{buildroot}%{_sysconfdir}/cron.daily
echo -e "#!/bin/sh\n%{_bindir}/squid-analyzer" > %{buildroot}%{_sysconfdir}/cron.daily/0%{name}

# Remove unpackaged files.
%{__rm} -f `find %{buildroot}/%{_libdir}/perl*/ -name .packlist -type f`
%{__rm} -f `find %{buildroot}/%{_libdir}/perl*/ -name perllocal.pod -type f`

%files
%defattr(-, root, root, 0755)
%doc README ChangeLog
%{_mandir}/man3/*
%{perl_vendorlib}/SquidAnalyzer.pm
%attr(0755,root,root) %{_bindir}/squid-analyzer
%attr(0755,root,root) %dir %{_sysconfdir}/%{name}
%attr(0664,root,root) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/excluded
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/included
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/network-aliases
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/user-aliases
%config(noreplace) %attr(0754,root,root) %{_sysconfdir}/cron.daily/0%{name}
%attr(0755,root,root) %dir %{_sysconfdir}/%{name}/lang
%{_sysconfdir}/%{name}/lang/*
%attr(0755,root,root) %dir %{contentdir}/%{name}
%{contentdir}/%{name}/flotr2.js
%{contentdir}/%{name}/sorttable.js
%{contentdir}/%{name}/%{name}.css
%attr(0755,root,root) %dir %{contentdir}/%{name}/images
%{contentdir}/%{name}/images/*.png

%clean
%{__rm} -rf %{buildroot}

