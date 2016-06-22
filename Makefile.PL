use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

use strict;

my @ALLOWED_ARGS = ('LOGFILE','BINDIR','ETCDIR', 'CONFDIR','HTMLDIR','BASEURL','DOCDIR','MANDIR','QUIET','INSTALLDIRS','DESTDIR');

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
my $ETCDIR = $ENV{ETCDIR} || $CONFDIR;
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
test ! -d "$DESTDIR$BINDIR" && mkdir -p $DESTDIR$BINDIR
test ! -d "$DESTDIR$ETCDIR" && mkdir -p $DESTDIR$ETCDIR
test ! -d "$DESTDIR$ETCDIR/lang" && mkdir -p $DESTDIR$ETCDIR/lang
test ! -d "$DESTDIR$HTMLDIR" && mkdir -p $DESTDIR$HTMLDIR
test ! -d "$DESTDIR$HTMLDIR/images" && mkdir -p $DESTDIR$HTMLDIR/images
};

if ($DOCDIR ne '') {
	print INST qq{
test ! -d "$DESTDIR$DOCDIR" && mkdir -p $DESTDIR$DOCDIR
};
}

print INST qq{
test ! -d "$DESTDIR$MANDIR" && mkdir -p $DESTDIR$MANDIR

# Copy files that must not be overriden 
for file in squidanalyzer.conf network-aliases user-aliases excluded included; do
if [ -r $DESTDIR$ETCDIR/\$file ]; then
	install -m 644 etc/\$file $DESTDIR$ETCDIR/\$file.sample
else
	install -m 644 etc/\$file $DESTDIR$ETCDIR/\$file
fi
done
install -m 755 squid-analyzer $DESTDIR$BINDIR/
install -m 644 resources/sorttable.js $DESTDIR$HTMLDIR/
install -m 644 resources/squidanalyzer.css $DESTDIR$HTMLDIR/
install -m 644 resources/flotr2.js $DESTDIR$HTMLDIR/
install -m 644 resources/images/logo-squidanalyzer.png $DESTDIR$HTMLDIR/images/
install -m 644 resources/images/cursor.png $DESTDIR$HTMLDIR/images/
install -m 644 resources/images/domain.png $DESTDIR$HTMLDIR/images/
install -m 644 resources/images/back-arrow.png $DESTDIR$HTMLDIR/images/
install -m 644 resources/images/info.png $DESTDIR$HTMLDIR/images/
install -m 644 resources/images/network.png $DESTDIR$HTMLDIR/images/
install -m 644 resources/images/user.png $DESTDIR$HTMLDIR/images/
install -m 644 lang/* $DESTDIR$ETCDIR/lang/
pod2text doc/SquidAnalyzer.pod README
pod2man doc/SquidAnalyzer.pod squid-analyzer.3
};
if ($DOCDIR ne '') {
        print INST qq{
	install -m 644 README $DESTDIR$DOCDIR/
	install -m 644 INSTALL $DESTDIR$DOCDIR/
	install -m 644 ChangeLog $DESTDIR$DOCDIR/
};
}
if ($MANDIR ne '') {
        print INST qq{
	install -m 644 squid-analyzer.3 $DESTDIR$MANDIR/
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
`perl -p -i -e 's#/.*/squidanalyzer.conf#$ETCDIR/squidanalyzer.conf#' etc/squidanalyzer.conf squid-analyzer`;
`perl -p -i -e 's#^Output.*#Output	$HTMLDIR#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#^LogFile.*#LogFile	$LOGFILE#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#^WebUrl.*#WebUrl	$BASEURL#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#^NetworkAlias.*#NetworkAlias	$ETCDIR/network-aliases#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#^UserAlias.*#UserAlias	$ETCDIR/user-aliases#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#^Exclude.*#Exclude	$ETCDIR/excluded#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#^Include.*#Include	$ETCDIR/included#' etc/squidanalyzer.conf`;
`perl -p -i -e 's#Lang.*\.txt#Lang	$ETCDIR/lang/en_US.txt#' etc/squidanalyzer.conf`;

my $zcat = `which zcat`;
chomp($zcat);
`perl -p -i -e 's#^\\\$ZCAT_PROG.*#\\\$ZCAT_PROG = "$zcat";#' SquidAnalyzer.pm`;

my $bzcat = `which bzcat`;
chomp($bzcat);
`perl -p -i -e 's#^\\\$BZCAT_PROG.*#\\\$BZCAT_PROG = "$bzcat";#' SquidAnalyzer.pm`;

my $xzcat = `which xzcat`;
chomp($xzcat);
`perl -p -i -e 's#^\\\$XZCAT_PROG.*#\\\$XZCAT_PROG = "$xzcat";#' SquidAnalyzer.pm`;


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
	'EXE_FILES'    => [ qw(squid-analyzer) ],
	'MAN3PODS'     => { 'doc/SquidAnalyzer.pod' => 'blib/man3/SquidAnalyzer.3pm' },
	'DESTDIR'      => $ENV{DESTDIR},
	'INSTALLDIRS'  => $ENV{INSTALLDIRS},
	'clean'	       => { FILES => "install_all.sh lib/blib/ squid-analyzer.3" },
	'META_MERGE'   => {
		resources  => {
			homepage => 'http://squidanalyzer.darold.net/',
			repository  => {
				type => 'git',
				git => 'git@github.com:darold/squidanalyzer.git',
				web => 'https://github.com/darold/squidanalyzer',
			},
		},
	}

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

