%define webdir /var/www

Summary:	Squid proxy log analyzer and report generator
Name:		squidanalyzer
Version:	6.6
Release:	1%{?dist}
License:	GPLv3+
Group:		Applications/Internet
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
# Build Makefile for SquidAnalyzer
%{__perl} Makefile.PL INSTALLDIRS=vendor DESTDIR=%{buildroot} LOGFILE=/var/log/squid/access.log BINDIR=%{_bindir} HTMLDIR=%{webdir}/%{name} BASEURL=/%{name} MANDIR=%{_mandir}/man3 QUIET=yes
# Compile
make

%install
# Clear buildroot from previous build
%{__rm} -rf %{buildroot}/

# Make install distrib files
%{__make} install

# Remove .packlist file (per rpmlint)
%{__rm} -f %{buildroot}/%perl_vendorarch/auto/SquidAnalyzer/.packlist
%{__rm} -f `find %{buildroot}/%{_libdir}/perl*/ -name .packlist -type f`
%{__rm} -f `find %{buildroot}/%{_libdir}/perl*/ -name perllocal.pod -type f`

# Install cron
%{__install} -d %{buildroot}/%{_sysconfdir}/cron.daily
echo -e "#!/bin/sh\n%{_bindir}/squid-analyzer" > %{buildroot}/%{_sysconfdir}/cron.daily/0%{name}

%files
%defattr(-, root, root, 0755)
%doc README ChangeLog
%{_mandir}/man3/squid-analyzer.3.gz
%{_mandir}/man3/SquidAnalyzer.3pm.gz
%{perl_vendorlib}/SquidAnalyzer.pm
%attr(0755,root,root) %{_bindir}/squid-analyzer
%attr(0755,root,root) %dir %{_sysconfdir}/%{name}
%attr(0664,root,root) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/excluded
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/included
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/network-aliases
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/user-aliases
%config(noreplace) %attr(0644,root,root) %{_sysconfdir}/%{name}/url-aliases
%config(noreplace) %attr(0754,root,root) %{_sysconfdir}/cron.daily/0%{name}
%attr(0755,root,root) %dir %{_sysconfdir}/%{name}/lang
%{_sysconfdir}/%{name}/lang/*
%attr(0755,root,root) %dir %{webdir}/%{name}
%{webdir}/%{name}/flotr2.js
%{webdir}/%{name}/sorttable.js
%{webdir}/%{name}/%{name}.css
%attr(0755,root,root) %dir %{webdir}/%{name}/images
%{webdir}/%{name}/images/*.png

%clean
%{__rm} -rf %{buildroot}

