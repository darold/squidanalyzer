%define contentdir /var/www

Summary:	Squid proxy log analyzer and report generator
Name:		squidanalyzer
Version:	4.2
Release:	%mkrel 1
License:	GPLv3
Group:		Monitoring
URL:		http://%{name}.darold.net/
Source:		http://prdownloads.sourceforge.net/squid-report/SquidAnalyzer-%{version}.tar.gz
Requires:	squid
BuildRequires:	perl

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

%setup -q -n SquidAnalyzer-%{version}

%build
perl Makefile.PL DESTDIR=%{buildroot} LOGFILE=%{_logdir}/squid/access.log BINDIR=%{_sbindir} HTMLDIR=%{contentdir}/html/%{name} BASEURL=/%{name} MANDIR=%{_mandir}/man3 QUIET=yes

%make

%install
rm -rf %{buildroot}

%makeinstall_std


%files
%defattr(-,root,squid)
%doc README ChangeLog
%{_mandir}/man3/*
%{perl_vendorlib}/SquidAnalyzer.pm
%attr(0755,root,squid) %{_sbindir}/squid-analyzer
%attr(0755,root,squid) %dir %{_sysconfdir}/%{name}
%attr(0664,root,squid) %config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %attr(0644,root,squid) %{_sysconfdir}/%{name}/excluded
%config(noreplace) %attr(0644,root,squid) %{_sysconfdir}/%{name}/network-aliases
%config(noreplace) %attr(0644,root,squid) %{_sysconfdir}/%{name}/user-aliases
%attr(0755,root,squid) %dir %{_sysconfdir}/%{name}/lang
%{_sysconfdir}/%{name}/lang/*
%attr(0755,root,squid) %dir %{contentdir}/html/%{name}
%{contentdir}/html/%{name}/logo-%{name}.png
%{contentdir}/html/%{name}/sorttable.js
%{contentdir}/html/%{name}/%{name}.css

%clean
rm -rf %{buildroot}

