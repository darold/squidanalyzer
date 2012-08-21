use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

use strict;

my @ALLOWED_ARGS = ('LOGFILE','BINDIR','CONFDIR','HTMLDIR','BASEURL','DOCDIR','MANDIR','QUIET','INSTALLDIRS','DESTDIR');

# Parse command line arguments and store them as environment variables
while ($_ = shift) {
	my ($k,$v) = split(/=/, $_, 2);
	if (grep(/^$k$/, @ALLOWED_ARGS)) {
		$ENV{$k} = $v;
	}
}
$ENV{DESTDIR} =~ s/\/$//;

# Search for default log dir
my $default_log = '/var/log/squid/access.log';
if (! -d $default_log ) {
	$default_log = '/var/log/squid3/access.log';
}

# Default install path
my $LOGFILE = $ENV{LOGFILE} || $default_log;
my $BINDIR = $ENV{BINDIR} || '/usr/local/bin';
my $CONFDIR = $ENV{CONFDIR} || '/etc/squidanalyzer';
my $HTMLDIR = $ENV{HTMLDIR} || '/var/www/squidanalyzer';
my $BASEURL = $ENV{BASEURL} || '/squidreport';
my $DOCDIR = $ENV{DOCDIR} || '';
my $MANDIR = $ENV{MANDIR} || '/usr/local/man/man3';
my $DESTDIR = $ENV{DESTDIR} || '';
$ENV{INSTALLDIRS} ||= 'vendor';

unless(open(INST, ">install_all.sh")) {
        print "\nError: can't write post install file install_all.sh, $!\n";
        exit 0;
}
print INST qq{#!/bin/sh
if [ ! -d "$DESTDIR$BINDIR" ]; then
        mkdir -p $DESTDIR$BINDIR
fi
if [ ! -d "$DESTDIR$CONFDIR" ]; then
        mkdir -p $DESTDIR$CONFDIR
        mkdir -p $DESTDIR$CONFDIR/lang
fi
if [ ! -d "$DESTDIR$HTMLDIR" ]; then
        mkdir -p $DESTDIR$HTMLDIR
fi
};

if ($DOCDIR ne '') {
	print INST qq{
if [ ! -d "$DESTDIR$DOCDIR" ]; then
	mkdir -p $DESTDIR$DOCDIR
fi
};
}

print INST qq{
if [ ! -d "$DESTDIR$MANDIR" ]; then
	mkdir -p $DESTDIR$MANDIR
fi

if [ -e "$DESTDIR$CONFDIR/squidanalyzer.conf" ]; then
        echo "File squidanalyzer.conf already exists. The new one will be copied as squidanalyzer.conf.new"
	install -m 644 squidanalyzer.conf $DESTDIR$CONFDIR/squidanalyzer.conf.new
else
	install -m 644 squidanalyzer.conf $DESTDIR$CONFDIR/
fi
install -m 755 squid-analyzer $DESTDIR$BINDIR/
install -m 644 sorttable.js $DESTDIR$HTMLDIR/
install -m 644 logo-squidanalyzer.png $DESTDIR$HTMLDIR/
install -m 644 squidanalyzer.css $DESTDIR$HTMLDIR/
install -m 644 lang/* $DESTDIR$CONFDIR/lang/
install -m 644 network-aliases $DESTDIR$CONFDIR/
install -m 644 user-aliases $DESTDIR$CONFDIR/
install -m 644 excluded $DESTDIR$CONFDIR/
pod2man doc/SquidAnalyzer.pod doc/squidanalyzer.3
install -m 644 doc/squidanalyzer.3 $DESTDIR$MANDIR/squidanalyzer.3
pod2text doc/SquidAnalyzer.pod README
};
if ($DOCDIR ne '') {
        print INST qq{
	install -m 644 README $DESTDIR$DOCDIR/
	install -m 644 INSTALL $DESTDIR$DOCDIR/
	install -m 644 ChangeLog $DESTDIR$DOCDIR/
};
}

if (!$ENV{QUIET}) {
        print INST qq{
echo "
-----------------------------------------------------------------------------
1. Modify your httpd.conf to allow access to HTML output like follow:
        Alias /squidreport $HTMLDIR
        <Directory $HTMLDIR>
            Options -Indexes FollowSymLinks MultiViews
	    AllowOverride None
            Order deny,allow
            Deny from all
            Allow from 127.0.0.1
        </Directory>
2. If necessary, give additional host access to SquidAnalyzer in httpd.conf.
   Restart and ensure that httpd is running.
3. Browse to http://my.host.dom/squidreport/ to ensure that things are working
   properly.
4. Setup a cronjob to run squid-analyzer daily:

     # SquidAnalyzer log reporting daily
     0 2 * * * $BINDIR/squid-analyzer > /dev/null 2>&1

or run it manually. For more information, see $DOCDIR/README file.
-----------------------------------------------------------------------------
"
};
}
close(INST);
`chmod 755 install_all.sh`;

# Change path into the default configuration file
`perl -p -i -e 's#/etc/squidanalyzer#$CONFDIR#' squidanalyzer.conf squid-analyzer`;
`perl -p -i -e 's#^Output.*#Output	$HTMLDIR#' squidanalyzer.conf`;
`perl -p -i -e 's#^LogFile.*#LogFile	$LOGFILE#' squidanalyzer.conf`;
`perl -p -i -e 's#^WebUrl.*#WebUrl	$BASEURL#' squidanalyzer.conf`;
my $zcat = `which zcat`;
chomp($zcat);
`perl -p -i -e 's#^\\\$ZCAT_PROG.*#\\\$ZCAT_PROG = "$zcat";#' SquidAnalyzer.pm`;

my $bzcat = `which bzcat`;
chomp($bzcat);
`perl -p -i -e 's#^\\\$BZCAT_PROG.*#\\\$BZCAT_PROG = "$bzcat";#' SquidAnalyzer.pm`;

WriteMakefile(
	'DISTNAME'	=> 'SquidAnalyzer',
	'NAME'		=> 'SquidAnalyzer',
	'VERSION_FROM' 	=> 'SquidAnalyzer.pm',
	'dist'  => {
			'COMPRESS'=>'gzip -9f', 'SUFFIX' => 'gz',
			'ZIP'=>'/usr/bin/zip','ZIPFLAGS'=>'-rl'
		   },
	'AUTHOR'       => 'Gilles Darold (gilles@darold.net)',
	'ABSTRACT'     => 'Squid log analyzer',
	'DESTDIR'      => $ENV{DESTDIR},
	'INSTALLDIRS'  => $ENV{INSTALLDIRS},
	clean	=> {FILES => "install_all.sh"},
);

sub MY::install {
	my $self = shift;

	my $string = $self->MM::install;
	$string =~ s/(pure_install\s+)(.*)/$1 install_all $2/;

	return $string;
}

sub MY::postamble {
	my $postamble = <<'END';
install_all: install_all.sh
	sh install_all.sh
END
	return $postamble;
}

if (!$ENV{QUIET}) {
	print "Done...\n\n";
	print "Now type 'make && make install'\n\n";
}

