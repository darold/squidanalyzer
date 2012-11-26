package SquidAnalyzer;
#------------------------------------------------------------------------------
# Project  : Squid Log Analyzer
# Name     : SquidAnalyzer.pm
# Language : Perl 5
# OS       : All
# Copyright: Copyright (c) 2001-2012 Gilles Darold - All rights reserved.
# Licence  : This program is free software; you can redistribute it
#            and/or modify it under the same terms as Perl itself.
# Author   : Gilles Darold, gilles _AT_ darold _DOT_ net
# Function : Main perl module for Squid Log Analyzer
# Usage    : See documentation.
#------------------------------------------------------------------------------
use strict;             # make things properly

BEGIN {
	use Exporter();
	use vars qw($VERSION $COPYRIGHT $AUTHOR @ISA @EXPORT $ZCAT_PROG $BZCAT_PROG);
	use POSIX;
	use GD;
	use GD::Graph;
	use GD::Graph::bars3d;
	use GD::Graph::pie3d;

	# Set all internal variable
	$VERSION = '4.4';
	$COPYRIGHT = 'Copyright (c) 2001-2012 Gilles Darold - All rights reserved.';
	$AUTHOR = "Gilles Darold - gilles _AT_ darold _DOT_ net";

	@ISA = qw(Exporter);
	@EXPORT = qw//;

	$| = 1;

}

$ZCAT_PROG = "/bin/zcat";
$BZCAT_PROG = "/bin/bzcat";

# Default translation srings
my %Translate = (
	'01' => 'Jan',
	'02' => 'Feb',
	'03' => 'Mar',
	'04' => 'Apr',
	'05' => 'May',
	'06' => 'Jun',
	'07' => 'Jul',
	'08' => 'Aug',
	'09' => 'Sep',
	'10' => 'Oct',
	'11' => 'Nov',
	'12' => 'Dec',
	'Bytes' => 'Bytes',
	'Total' => 'Total',
	'Years' => 'Years',
	'Users' => 'Users',
	'Sites' => 'Sites',
	'Cost' => 'Cost',
	'Requests' => 'Requests',
	'Megabytes' => 'Mega bytes',
	'Months' => 'Months',
	'Days' => 'Days',
	'Hit' => 'Hit',
	'Miss' => 'Miss',
	'Domains' => 'Domains',
	'Requests_graph' => 'Requests',
	'Megabytes_graph' => 'Mega bytes',
	'Months_graph' => 'Months',
	'Days_graph' => 'Days',
	'Hit_graph' => 'Hit',
	'Miss_graph' => 'Miss',
	'Total_graph' => 'Total',
	'Domains_graph' => 'Domains',
	'Users_help' => 'Total number of different users for this period',
	'Sites_help' => 'Total number of different visited sites for this period',
	'Domains_help' => 'Total number of different second level visited domain for this period',
	'Hit_help' => 'Objects found in cache',
	'Miss_help' => 'Objects not found in cache',
	'Cost_help' => '1 Mega byte =',
	'Generation' => 'Report generated on',
	'Main_cache_title' => 'Cache Statistics',
	'Cache_title' => 'Cache Statistics on',
	'Stat_label' => 'Stat',
	'Mime_link' => 'Mime Types',
	'Network_link' => 'Networks',
	'User_link' => 'Users',
	'Top_url_link' => 'Top Urls',
	'Top_domain_link' => 'Top Domains',
	'Back_link' => 'Back',
	'Up_link' => 'Up',
	'Graph_cache_hit_title' => '%s Requests statistics on',
	'Graph_cache_byte_title' => '%s Mega Bytes statistics on',
	'Hourly' => 'Hourly',
	'Hours' => 'Hours',
	'Daily' => 'Daily',
	'Days' => 'Days',
	'Monthly' => 'Monthly',
	'Months' => 'Months',
	'Mime_title' => 'Mime Type Statistics on',
	'Mime_number' => 'Number of mime type',
	'Network_title' => 'Network Statistics on',
	'Network_number' => 'Number of network',
	'Duration' => 'Duration',
	'Time' => 'Time',
	'Largest' => 'Largest',
	'Url' => 'Url',
	'User_title' => 'User Statistics on',
	'User_number' => 'Number of user',
	'Url_Hits_title' => 'Top %d Url hits on',
	'Url_Bytes_title' => 'Top %d Url bytes on',
	'Url_Duration_title' => 'Top %d Url duration on',
	'Url_number' => 'Number of Url',
	'Domain_Hits_title' => 'Top %d Domain hits on',
	'Domain_Bytes_title' => 'Top %d Domain bytes on',
	'Domain_Duration_title' => 'Top %d Domain duration on',
	'Domain_number' => 'Number of domain',
	'Domain_graph_hits_title' => 'Domain Hits Statistics on',
	'Domain_graph_bytes_title' => 'Domain Bytes Statistiques on',
	'First_visit' => 'First visit',
	'Last_visit' => 'Last visit',
);


sub new
{
	my ($class, $conf_file, $log_file) = @_;

	# Construct the class
	my $self = {};
	bless $self, $class;

	# Initialize all variables
	$self->_init($conf_file, $log_file);

	# Return the instance
	return($self);

}

sub parseFile
{
	my ($self) = @_;

	return if ((!-f $self->{LogFile}) || (-z $self->{LogFile}));

	# The log file format must be :
	# 	time elapsed client code/status bytes method URL rfc931 peerstatus/peerhost type
	# This is the default format of squid access log file.

	# Open logfile
	my $logfile = new IO::File;
	if ($self->{LogFile} =~ /\.gz/) {
		# Open a pipe to zcat program for compressed log
		$logfile->open("$ZCAT_PROG $self->{LogFile} |") || die "ERROR: cannot read from pipe to $ZCAT_PROG $self->{LogFile}. $!\n";
	} elsif ($self->{LogFile} =~ /\.bz2/) {
		# Open a pipe to zcat program for compressed log
		$logfile->open("$BZCAT_PROG $self->{LogFile} |") || die "ERROR: cannot read from pipe to $BZCAT_PROG $self->{LogFile}. $!\n";
	} else {
		$logfile->open($self->{LogFile}) || die "ERROR: Unable to open Squid access.log file $self->{LogFile}. $!\n";
	}

	my $line = '';
	my $time = 0;
	my $elapsed = 0;
	my $client_ip = '';
	my $client_name = '';
	my $code = '';
	my $bytes = 0;
	my $method = '';
	my $url = '';
	my $login = '';
	my $status = '';
	my $mime_type = '';

	my $line_count = 0;
	my $line_processed_count = 0;
	my $line_stored_count = 0;
	# Read and parse each line of the access log file
	while ($line = <$logfile>) {
		chomp($line);
		#logformat squid %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %un %Sh/%<A %mt
		#logformat squidmime %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %un %Sh/%<A %mt [%>h] [%<h]
		# The log format below are not supported
		#logformat common %>a %ui %un [%tl] "%rm %ru HTTP/%rv" %>Hs %<st %Ss:%Sh
		#logformat combined %>a %ui %un [%tl] "%rm %ru HTTP/%rv" %>Hs %<st "%{Referer}>h" "%{User-Agent}>h" %Ss:%Sh
		# Parse log with format: time elapsed client code/status bytes method URL rfc931 peerstatus/peerhost mime_type
		if ( $line =~ s#^(\d+\.\d{3})\s+(\d+)\s+([^\s]+)\s+([^\s]+)\s+(\d+)\s+([^\s]+)\s+## ) {
			$time = $1 || 0;
			$elapsed = $2 || 0;
			$code = $4 || '';
			$bytes = $5 || 0;
			$method = $6 || '';
			$client_ip = $3 || '';

			# Go to last parsed date (incremental mode)
			next if ($self->{history_time} && ($time <= $self->{history_time}));

			# Register the last parsing time
			$self->{end_time} = $time;

			# Register the first parsing time
			if (!$self->{begin_time}) {
				$self->{begin_time} = $time;
				print STDERR "START TIME: ", strftime("%a %b %e %H:%M:%S %Y", localtime($time)), "\n" if (!$self->{QuietMode});
			}
			# Only store (HIT|UNMODIFIED)/MISS status and peer CD_SIBLING_HIT/...
			if ( ($code =~ m#(HIT|UNMODIFIED)/#) || ($self->{SiblingHit} && ($line =~ / CD_SIBLING_HIT/)) ) {
				$code = 'HIT';
			} elsif ($code =~ m#MISS|MODIFIED/#) {
				$code = 'MISS';
			} else {
				next;
			}

			if ( $line =~ s#^(.*)\s+([^\s]+)\s+([^\s]+\/[^\s]+)\s+([^\s]+)\s*## ) {
				$url = lc($1) || '';
				$login = lc($2) || '';
				$status = lc($3) || '';
				$mime_type = lc($4) || '';
				$mime_type = 'none' if (!$mime_type || ($mime_type eq '-'));
				# Remove extra space character in username
				$login =~ s/\%20//g;

				my $id = $client_ip || '';
				if ($login ne '-') {
					$id = $login;
				}
				next if (!$id || !$bytes);
				# check for client/user exclusion in old syntax
				my $found = 0;
				if (exists $self->{Exclude}{all}) {
					foreach my $e (@{$self->{Exclude}{all}}) {
						if ( ($client_ip =~ m#^$e$#i) || ($login =~ m#^$e$#i)) {
							$found = 1;
							last;
						}
					} 
					next if ($found);
				}
				# check for user exclusion
				if (exists $self->{Exclude}{users}) {
					foreach my $e (@{$self->{Exclude}{users}}) {
						if ($login =~ m#^$e$#i) {
							$found = 1;
							last;
						}
					} 
					next if ($found);
				}
				# check for client exclusion
				if (exists $self->{Exclude}{clients}) {
					foreach my $e (@{$self->{Exclude}{clients}}) {
						if ($client_ip =~ m#^$e$#i) {
							$found = 1;
							last;
						}
					} 
					next if ($found);
				}
				# check for URL exclusion
				if (exists $self->{Exclude}{uris}) {
					foreach my $e (@{$self->{Exclude}{uris}}) {
						if ($url =~ m#^$e$#i) {
							$found = 1;
							last;
						}
					}
					next if ($found);
				}
				# Anonymize all users
				if ($self->{AnonymizeLogin} && ($client_ip ne $id)) {
					if (!exists $self->{AnonymizedId}{$id}) {
						$self->{AnonymizedId}{$id} = &anonymize_id();
					}
					$id = $self->{AnonymizedId}{$id};
				}
				# Now parse data and generate statistics
				$self->_parseData($time, $elapsed, $client_ip, $code, $bytes, $url, $id, $mime_type);
				$line_stored_count++;
			}
			$line_processed_count++;
		}
		$line_count++;
	}
	$logfile->close();

	if (!$self->{last_year} && !$self->{last_month} && !$self->{last_day}) {
		print STDERR "No new log registered...\n" if (!$self->{QuietMode});
	} else {
		# Save last parsed data
		$self->_save_data("$self->{last_year}", "$self->{last_month}", "$self->{last_day}");

		if (!$self->{QuietMode}) {
			print STDERR "END TIME  : ", strftime("%a %b %e %H:%M:%S %Y", localtime($self->{end_time})), "\n";
			print "Read $line_count lines, matched $line_processed_count and found $line_stored_count new lines\n";
		}

		# Set the current start time into history file
		if ($self->{end_time}) {
			my $current = new IO::File;
			$current->open(">$self->{Output}/SquidAnalyzer.current") or die "Error: Can't write to file $self->{Output}/SquidAnalyzer.current, $!\n";
			print $current "$self->{end_time}";
			$current->close;
		}

		# Compute month statistics
		if (!$self->{QuietMode}) {
			print STDERR "\nParsing ended, generating data files now...\n";
			print STDERR "Compute and dump month statistics for $self->{first_year}/$self->{first_month} to $self->{last_year}/$self->{last_month}\n";
		}
		for my $date ("$self->{first_year}$self->{first_month}" .. "$self->{last_year}$self->{last_month}") {
			$date =~ /^(\d{4})(\d{2})$/;
			next if (($2 < 1) || ($2 > 12));
			if (-d "$self->{Output}/$1/$2") {
				$self->_save_data("$1", "$2");
			}
		}

		# Compute year statistics
		if (!$self->{QuietMode}) {
			print STDERR "Compute and dump year statistics for $self->{first_year} to $self->{last_year}\n";
		}
		for my $year ($self->{first_year} .. $self->{last_year}) {
			if (-d "$self->{Output}/$year") {
				$self->_save_data($year);
			}
		}
	}

}

sub _clear_stats
{
	my $self = shift;

	# Hashes to store user statistics
	$self->{stat_user_hour} = ();
	$self->{stat_user_day} = ();
	$self->{stat_user_month} = ();
	$self->{stat_usermax_hour} = ();
	$self->{stat_usermax_day} = ();
	$self->{stat_usermax_month} = ();
	$self->{stat_user_url_hour} = ();
	$self->{stat_user_url_day} = ();
	$self->{stat_user_url_month} = ();

	# Hashes to store network statistics
	$self->{stat_network_hour} = ();
	$self->{stat_network_day} = ();
	$self->{stat_network_month} = ();
	$self->{stat_netmax_hour} = ();
	$self->{stat_netmax_day} = ();
	$self->{stat_netmax_month} = ();

	# Hashes to store user / network statistics
	$self->{stat_netuser_hour} = ();
	$self->{stat_netuser_day} = ();
	$self->{stat_netuser_month} = ();

	# Hashes to store cache status (hit/miss)
	$self->{stat_code_hour} = ();
	$self->{stat_code_day} = ();
	$self->{stat_code_month} = ();

	# Hashes to store mime type
	$self->{stat_mime_type_hour} = ();
	$self->{stat_mime_type_day} = ();
	$self->{stat_mime_type_month} = ();

}

sub _init
{
	my ($self, $conf_file, $log_file) = @_;

	# Prevent for a call without instance
	if (!ref($self)) {
		print "ERROR - init : Unable to call init without an object instance.\n";
		exit(0);
	}

	# Load configuration information
	if (!$conf_file) {
		if (-f '/etc/squidanalyzer.conf') {
			$conf_file = '/etc/squidanalyzer.conf';
		} elsif (-f 'squidanalyzer.conf') {
			$conf_file = 'squidanalyzer.conf';
		}
	}
	my %options = &parse_config($conf_file);

	# Use squid log file given as command line parameter
	$options{LogFile} = $log_file if ($log_file);

	# Configuration options
	$self->{QuietMode} = $options{QuietMode} || 0;
	$self->{UrlReport} = $options{UrlReport} || 0;
	$self->{Output} = $options{Output} || '';
	$self->{WebUrl} = $options{WebUrl} || '';
	$self->{WebUrl} .= '/' if ($self->{WebUrl} && ($self->{WebUrl} !~ /\/$/));
	$self->{DateFormat} = $options{DateFormat} || '%y-%m-%d';
	$self->{Lang} = $options{Lang} || '';
	$self->{HeaderFile} = $options{HeaderFile} || '';
	$self->{FooterFile} = $options{FooterFile} || '';
	$self->{AnonymizeLogin} = $options{AnonymizeLogin} || 0;
	$self->{SiblingHit} = $options{SiblingHit} || 1;
	if ($self->{Lang}) {
		open(IN, "$self->{Lang}") or die "ERROR: can't open translation file $self->{Lang}, $!\n";
		while (my $l = <IN>) {
			chomp($l);
			next if ($l =~ /^[\s\t]*#/);
			next if (!$l);
			my ($key, $str) = split(/\t+/, $l);
			$Translate{$key} = $str;
		}
		close(IN);
	}
	if ($self->{HeaderFile}) {
		open(IN, "$self->{HeaderFile}") or die "ERROR: can't open header file $self->{HeaderFile}, $!\n";
		$self->{HeaderFile} = '';
		while (my $l = <IN>) {
			$self->{HeaderFile} .= $l;
		}
		close(IN);
	}
	if ($self->{FooterFile}) {
		open(IN, "$self->{FooterFile}") or die "ERROR: can't open footer file $self->{FooterFile}, $!\n";
		$self->{FooterFile} = '';
		while (my $l = <IN>) {
			$self->{FooterFile} .= $l;
		}
		close(IN);
	}
	if (!$self->{Output}) {
		die "ERROR: 'Output' configuration option must be set.\n";
	}
	if (! -d $self->{Output}) {
		die "ERROR: 'Output' dorectory $self->{Output} doesn't exists.\n";
	}
	$self->{LogFile} = $options{LogFile} || '/var/log/squid/access.log';
	if (!$self->{LogFile}) {
		die "ERROR: 'LogFile' configuration option must be set.\n";
	}
	if (! -e $self->{LogFile}) {
		die "ERROR: 'LogFile' $self->{LogFile} doesn't exists.\n";
	}
	$self->{OrderUser} = lc($options{OrderUser}) || 'bytes';
	$self->{OrderNetwork} = lc($options{OrderNetwork}) || 'bytes';
	$self->{OrderUrl} = lc($options{OrderUrl}) || 'bytes';
	$self->{OrderMime} = lc($options{OrderMime}) || 'bytes';
	if ($self->{OrderUser} !~ /^(hits|bytes|duration)$/) {
		die "ERROR: OrderUser must be one of these values: hits, bytes or duration\n";
	}
	if ($self->{OrderNetwork} !~ /^(hits|bytes|duration)$/) {
		die "ERROR: OrderNetwork must be one of these values: hits, bytes or duration\n";
	}
	if ($self->{OrderUrl} !~ /^(hits|bytes|duration)$/) {
		die "ERROR: OrderUrl must be one of these values: hits, bytes or duration\n";
	}
	if ($self->{OrderMime} !~ /^(hits|bytes)$/) {
		die "ERROR: OrderMime must be one of these values: hits or bytes\n";
	}
	$self->{NetworkAlias} = &parse_network_aliases($options{NetworkAlias} || '');
	$self->{UserAlias} = &parse_user_aliases($options{UserAlias} || '');
	%{$self->{Exclude}} = &parse_exclusion($options{Exclude} || '');

	$self->{CostPrice} = $options{CostPrice} || 0;
	$self->{Currency} = $options{Currency} || '&euro;';
	$self->{TopNumber} = $options{TopNumber} || 10;

	# Init statistics storage hashes
	$self->_clear_stats();

	# Used to store the first and last date parsed
        $self->{last_year} = 0;
        $self->{last_month} = 0;
        $self->{last_day} = 0;
        $self->{first_year} = 0;
        $self->{first_month} = 0;
        $self->{first_day} = 0;
	$self->{begin_time} = 0;
	$self->{end_time} = 0;
	$self->{history_time} = 0;

	# Get the last parsing date for incremental parsing
	if (-e "$self->{Output}/SquidAnalyzer.current") {
		my $current = new IO::File;
		unless($current->open("$self->{Output}/SquidAnalyzer.current")) {
			print STDERR "ERROR: Can't read file $self->{Output}/SquidAnalyzer.current, $!\n" if (!$self->{QuietMode});
			print STDERR "Starting at the first line of Squid access log file.\n" if (!$self->{QuietMode});
		} else {
			$self->{history_time} = <$current>;
			chomp($self->{history_time});
			$self->{begin_time} = $self->{history_time};
			$current->close();
			print STDERR "HISTORY TIME: ", strftime("%a %b %e %H:%M:%S %Y", localtime($self->{history_time})), "\n" if (!$self->{QuietMode});
		}
	}

	$self->{menu} = qq{
<div id="menu">
<table>
<tr>
<th><a href="mime_type.html">[ $Translate{'Mime_link'} ]</a></th>
<th><a href="network.html">[ $Translate{'Network_link'} ]</a></th>
<th><a href="user.html">[ $Translate{'User_link'} ]</a></th>
};
	if ($self->{UrlReport}) {
		$self->{menu} .= qq{
<th><a href="url.html">[ $Translate{'Top_url_link'} ]</a></th>
<th><a href="domain.html">[ $Translate{'Top_domain_link'} ]</a></th>};
	}
	$self->{menu} .= qq{
<th><a href="../index.html">[ $Translate{'Back_link'} ]</a></th>
</tr>
</table>
</div>
};

	$self->{menu2} = qq{
<div id="menu">
<table>
<tr>
<th><a href="../../mime_type.html">[ $Translate{'Mime_link'} ]</a></th>
<th><a href="../../network.html">[ $Translate{'Network_link'} ]</a></th>
<th><a href="../../user.html">[ $Translate{'User_link'} ]</a></th>
};
	if ($self->{UrlReport}) {
		$self->{menu2} .= qq{
<th><a href="../../url.html">[ $Translate{'Top_url_link'} ]</a></th>
<th><a href="../../domain.html">[ $Translate{'Top_domain_link'} ]</a></th>};
	}
	$self->{menu2} .= qq{
<th><a href="../../index.html">[ $Translate{'Back_link'} ]</a></th>
</tr>
</table>
</div>
};


}

sub _parseData
{
	my ($self, $time, $elapsed, $client, $code, $bytes, $url, $id, $type) = @_;

	# Get the current year and month
	my ($sec,$min,$hour,$wday,$yday,$isdst) = '';
	($sec,$min,$hour,$self->{last_day},$self->{last_month},$self->{last_year},$wday,$yday,$isdst) = localtime($time);
	$self->{last_year} += 1900;
	$self->{last_month}++;
	$self->{last_month} = "0$self->{last_month}" if ($self->{last_month} < 10);
	$self->{last_day} = "0$self->{last_day}" if ($self->{last_day} < 10);
	$hour = "0$hour" if ($hour < 10);

	# Set the year/month value for history check
	my $date = "$self->{last_year}$self->{last_month}$self->{last_day}";

	# Extract the domainname part of the URL
	my $dest = $url;
	$dest =~ s#^[^\/]*\/\/##;
	$dest =~ s#\/.*##;
	$dest =~ s#:\d+$##;

	# Replace network by his aliases if any
	my $network = '';
	foreach my $n (keys %{$self->{NetworkAlias}}) {
		if ( grep($client =~ /^$_/,  @{$self->{NetworkAlias}->{$n}}) ) {
			$network = $n;
			last;
		}
	}
	# Set default to a class A network
	if (!$network) {
		$network = $client;
		$network =~ s/\.\d+$/\.0/;
	}
	# Replace username by his alias if any
	foreach my $u (keys %{$self->{UserAlias}}) {
		if ( grep($id =~ /^$_$/,  @{$self->{UserAlias}->{$u}}) ) {
			$id = $u;
			last;
		}
	}

	# Store data when day change to save memory
	if ($self->{tmp_saving} =~ /^(\d{4})(\d{2})(\d{2})$/) {
		# If the day has changed then we want to save stats of the previous one
		if ($self->{last_day} && ($3 ne $self->{last_day})) {
			$self->_save_data("$1", "$2", "$3");
			$self->{first_day} = '';
		}
		# If the month has changed then we want to save stats of the previous one
		if ($self->{last_month} && ($2 ne $self->{last_month})) {
			$self->_save_data("$1", "$2");
			$self->{first_month} = '';
		}
		# If the year has changed then we want to save stats of the previous one
		if ($self->{last_year} && ($1 ne $self->{last_year})) {
			$self->_save_data("$1");
			$self->{first_year} = '';
			# Stats can be cleared
			print STDERR "Clearing complete statistics storage hashes for year $1.\n" if (!$self->{QuietMode});
			$self->_clear_stats();
		}
	}

	$self->{first_year} ||= $self->{last_year};
	$self->{first_month} ||= $self->{last_month};
	$self->{first_day} ||= $self->{last_day};

	$self->{tmp_saving} = $date;

	#### Store client statistics
	$self->{stat_user_hour}{$id}{$hour}{hits}++;
	$self->{stat_user_hour}{$id}{$hour}{bytes} += $bytes;
	$self->{stat_user_hour}{$id}{$hour}{duration} += $elapsed;
	$self->{stat_user_day}{$id}{$self->{last_day}}{hits}++;
	$self->{stat_user_day}{$id}{$self->{last_day}}{bytes} += $bytes;
	$self->{stat_user_day}{$id}{$self->{last_day}}{duration} += $elapsed;
	$self->{stat_user_month}{$id}{$self->{last_month}}{hits}++;
	$self->{stat_user_month}{$id}{$self->{last_month}}{bytes} += $bytes;
	$self->{stat_user_month}{$id}{$self->{last_month}}{duration} += $elapsed;
	if ($bytes > $self->{stat_usermax_hour}{$id}{largest_file_size}) {
		$self->{stat_usermax_hour}{$id}{largest_file_size} = $bytes;
		$self->{stat_usermax_hour}{$id}{largest_file_url} = $url;
	}
	if ($bytes > $self->{stat_usermax_day}{$id}{largest_file_size}) {
		$self->{stat_usermax_day}{$id}{largest_file_size} = $bytes;
		$self->{stat_usermax_day}{$id}{largest_file_url} = $url;
	}
	if ($bytes > $self->{stat_usermax_month}{$id}{largest_file_size}) {
		$self->{stat_usermax_month}{$id}{largest_file_size} = $bytes;
		$self->{stat_usermax_month}{$id}{largest_file_url} = $url;
	}

	#### Store networks statistics
	$self->{stat_network_hour}{$network}{$hour}{hits}++;
	$self->{stat_network_hour}{$network}{$hour}{bytes} += $bytes;
	$self->{stat_network_hour}{$network}{$hour}{duration} += $elapsed;
	$self->{stat_network_day}{$network}{$self->{last_day}}{hits}++;
	$self->{stat_network_day}{$network}{$self->{last_day}}{bytes} += $bytes;
	$self->{stat_network_day}{$network}{$self->{last_day}}{duration} += $elapsed;
	$self->{stat_network_month}{$network}{$self->{last_month}}{hits}++;
	$self->{stat_network_month}{$network}{$self->{last_month}}{bytes} += $bytes;
	$self->{stat_network_month}{$network}{$self->{last_month}}{duration} += $elapsed;
	if ($bytes > $self->{stat_netmax_hour}{$network}{largest_file_size}) {
		$self->{stat_netmax_hour}{$network}{largest_file_size} = $bytes;
		$self->{stat_netmax_hour}{$network}{largest_file_url} = $url;
	}
	if ($bytes > $self->{stat_netmax_day}{$network}{largest_file_size}) {
		$self->{stat_netmax_day}{$network}{largest_file_size} = $bytes;
		$self->{stat_netmax_day}{$network}{largest_file_url} = $url;
	}
	if ($bytes > $self->{stat_netmax_month}{$network}{largest_file_size}) {
		$self->{stat_netmax_month}{$network}{largest_file_size} = $bytes;
		$self->{stat_netmax_month}{$network}{largest_file_url} = $url;
	}

	#### Store HIT/MISS statistics
	$self->{stat_code_hour}{$code}{$hour}{hits}++;
	$self->{stat_code_hour}{$code}{$hour}{bytes} += $bytes;
	$self->{stat_code_day}{$code}{$self->{last_day}}{hits}++;
	$self->{stat_code_day}{$code}{$self->{last_day}}{bytes} += $bytes;
	$self->{stat_code_month}{$code}{$self->{last_month}}{hits}++;
	$self->{stat_code_month}{$code}{$self->{last_month}}{bytes} += $bytes;

	#### Store url statistics
	if ($self->{UrlReport}) {
		$self->{stat_user_url_hour}{$id}{$dest}{duration} += $elapsed;
		$self->{stat_user_url_hour}{$id}{$dest}{hits}++;
		$self->{stat_user_url_hour}{$id}{$dest}{bytes} += $bytes;
		$self->{stat_user_url_hour}{$id}{$dest}{firsthit} = $time if (!$self->{stat_user_url_hour}{$id}{$dest}{firsthit});
		$self->{stat_user_url_hour}{$id}{$dest}{lasthit} = $time;
		$self->{stat_user_url_day}{$id}{$dest}{duration} += $elapsed;
		$self->{stat_user_url_day}{$id}{$dest}{hits}++;
		$self->{stat_user_url_day}{$id}{$dest}{firsthit} = $time if (!$self->{stat_user_url_day}{$id}{$dest}{firsthit});
		$self->{stat_user_url_day}{$id}{$dest}{lasthit} = $time;
		$self->{stat_user_url_day}{$id}{$dest}{bytes} += $bytes;
		$self->{stat_user_url_month}{$id}{$dest}{duration} += $elapsed;
		$self->{stat_user_url_month}{$id}{$dest}{hits}++;
		$self->{stat_user_url_month}{$id}{$dest}{bytes} += $bytes;
	}

	#### Store user per networks statistics
	$self->{stat_netuser_hour}{$network}{$id}{duration} += $elapsed;
	$self->{stat_netuser_hour}{$network}{$id}{bytes} += $bytes;
	$self->{stat_netuser_hour}{$network}{$id}{hits}++;
	if ($bytes > $self->{stat_netuser_hour}{$network}{$id}{largest_file_size}) {
		$self->{stat_netuser_hour}{$network}{$id}{largest_file_size} = $bytes;
		$self->{stat_netuser_hour}{$network}{$id}{largest_file_url} = $url;
	}
	$self->{stat_netuser_day}{$network}{$id}{duration} += $elapsed;
	$self->{stat_netuser_day}{$network}{$id}{bytes} += $bytes;
	$self->{stat_netuser_day}{$network}{$id}{hits}++;
	if ($bytes > $self->{stat_netuser_day}{$network}{$id}{largest_file_size}) {
		$self->{stat_netuser_day}{$network}{$id}{largest_file_size} = $bytes;
		$self->{stat_netuser_day}{$network}{$id}{largest_file_url} = $url;
	}
	$self->{stat_netuser_month}{$network}{$id}{duration} += $elapsed;
	$self->{stat_netuser_month}{$network}{$id}{bytes} += $bytes;
	$self->{stat_netuser_month}{$network}{$id}{hits}++;
	if ($bytes > $self->{stat_netuser_month}{$network}{$id}{largest_file_size}) {
		$self->{stat_netuser_month}{$network}{$id}{largest_file_size} = $bytes;
		$self->{stat_netuser_month}{$network}{$id}{largest_file_url} = $url;
	}

	#### Store mime type statistics
	$self->{stat_mime_type_hour}{"$type"}{hits}++;
	$self->{stat_mime_type_hour}{"$type"}{bytes} += $bytes;
	$self->{stat_mime_type_day}{"$type"}{hits}++;
	$self->{stat_mime_type_day}{"$type"}{bytes} += $bytes;
	$self->{stat_mime_type_month}{"$type"}{hits}++;
	$self->{stat_mime_type_month}{"$type"}{bytes} += $bytes;

}

sub _save_stat
{
	my ($self, $year, $month, $day) = @_;

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	my $path = join('/', $year, $month, $day);
	$path =~ s/[\/]+$//;

	#### Load history
	$self->_read_stat($year, $month, $day);

	#### Save url statistics per user
	if ($self->{UrlReport}) {
		my $dat_file_user_url = new IO::File;
		$dat_file_user_url->open(">$self->{Output}/$path/stat_user_url.dat")
			or die "ERROR: Can't write to file $self->{Output}/$path/stat_user_url.dat, $!\n";
		foreach my $id (sort {$a cmp $b} keys %{$self->{"stat_user_url_$type"}}) {
			foreach my $dest (keys %{$self->{"stat_user_url_$type"}{$id}}) {
				$dat_file_user_url->print("$id hits=" . $self->{"stat_user_url_$type"}{$id}{$dest}{hits} . ";" .
					"bytes=" . $self->{"stat_user_url_$type"}{$id}{$dest}{bytes} . ";" .
					"duration=" . $self->{"stat_user_url_$type"}{$id}{$dest}{duration} . ";" .
					"first=" . $self->{"stat_user_url_$type"}{$id}{$dest}{firsthit} . ";" .
					"last=" . $self->{"stat_user_url_$type"}{$id}{$dest}{lasthit} . ";" .
					"url=$dest\n");
			}
		}
		$dat_file_user_url->close();
		$self->{"stat_user_url_$type"} = ();
	}

	#### Save user statistics
	my $dat_file_user = new IO::File;
	$dat_file_user->open(">$self->{Output}/$path/stat_user.dat")
		or die "ERROR: Can't write to file $self->{Output}/$path/stat_user.dat, $!\n";
	foreach my $id (sort {$a cmp $b} keys %{$self->{"stat_user_$type"}}) {
		my $name = $id;
		$name =~ s/\s+//g;
		$dat_file_user->print("$name hits_$type="); 
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_user_$type"}{$id}}) {
			$dat_file_user->print("$tmp:" . $self->{"stat_user_$type"}{$id}{$tmp}{hits} . ",");
		}
		$dat_file_user->print(";bytes_$type=");
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_user_$type"}{$id}}) {
			$dat_file_user->print("$tmp:" . $self->{"stat_user_$type"}{$id}{$tmp}{bytes} . ",");
		}
		$dat_file_user->print(";duration_$type=");
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_user_$type"}{$id}}) {
			$dat_file_user->print("$tmp:" . $self->{"stat_user_$type"}{$id}{$tmp}{duration} . ",");
		}
		$dat_file_user->print(";largest_file_size=" . $self->{"stat_usermax_$type"}{$id}{largest_file_size});
		$dat_file_user->print(";largest_file_url=" . $self->{"stat_usermax_$type"}{$id}{largest_file_url} . "\n");
	}
	$dat_file_user->close();
	$self->{"stat_user_$type"} = ();
	$self->{"stat_usermax_$type"} = ();

	#### Save network statistics
	my $dat_file_network = new IO::File;
	$dat_file_network->open(">$self->{Output}/$path/stat_network.dat")
		or die "ERROR: Can't write to file $self->{Output}/$path/stat_network.dat, $!\n";
	foreach my $net (sort {$a cmp $b} keys %{$self->{"stat_network_$type"}}) {
		$dat_file_network->print("$net\thits_$type="); 
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_network_$type"}{$net}}) {
			$dat_file_network->print("$tmp:" . $self->{"stat_network_$type"}{$net}{$tmp}{hits} . ",");
		}
		$dat_file_network->print(";bytes_$type=");
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_network_$type"}{$net}}) {
			$dat_file_network->print("$tmp:" . $self->{"stat_network_$type"}{$net}{$tmp}{bytes} . ",");
		}
		$dat_file_network->print(";duration_$type=");
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_network_$type"}{$net}}) {
			$dat_file_network->print("$tmp:" . $self->{"stat_network_$type"}{$net}{$tmp}{duration} . ",");
		}
		$dat_file_network->print(";largest_file_size=" . $self->{"stat_netmax_$type"}{$net}{largest_file_size});
		$dat_file_network->print(";largest_file_url=" . $self->{"stat_netmax_$type"}{$net}{largest_file_url} . "\n");
	}
	$dat_file_network->close();
	$self->{"stat_network_$type"} = ();
	$self->{"stat_netmax_$type"} = ();

	#### Save user per network statistics
	my $dat_file_netuser = new IO::File;
	$dat_file_netuser->open(">$self->{Output}/$path/stat_netuser.dat")
		or die "ERROR: Can't write to file $self->{Output}/$path/stat_netuser.dat, $!\n";
	foreach my $net (sort {$a cmp $b} keys %{$self->{"stat_netuser_$type"}}) {
		foreach my $id (sort {$a cmp $b} keys %{$self->{"stat_netuser_$type"}{$net}}) {
			$dat_file_netuser->print("$net\t$id\thits=" . $self->{"stat_netuser_$type"}{$net}{$id}{hits} . ";" .
				"bytes=" . $self->{"stat_netuser_$type"}{$net}{$id}{bytes} . ";" .
				"duration=" . $self->{"stat_netuser_$type"}{$net}{$id}{duration} . ";");
			$dat_file_netuser->print("largest_file_size=" .
				$self->{"stat_netuser_$type"}{$net}{$id}{largest_file_size} . ";" .
				"largest_file_url=" . $self->{"stat_netuser_$type"}{$net}{$id}{largest_file_url} . "\n");
		}
	}
	$dat_file_netuser->close();
	$self->{"stat_netuser_$type"} = ();


	#### Save cache statistics
	my $dat_file_code = new IO::File;
	$dat_file_code->open(">$self->{Output}/$path/stat_code.dat")
		or die "ERROR: Can't write to file $self->{Output}/$path/stat_code.dat, $!\n";
	foreach my $code (sort {$a cmp $b} keys %{$self->{"stat_code_$type"}}) {
		$dat_file_code->print("$code " .
			"hits_$type=");
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_code_$type"}{$code}}) {
			$dat_file_code->print("$tmp:" . $self->{"stat_code_$type"}{$code}{$tmp}{hits} . ",");
		}
		$dat_file_code->print(";bytes_$type=");
		foreach my $tmp (sort {$a <=> $b} keys %{$self->{"stat_code_$type"}{$code}}) {
			$dat_file_code->print("$tmp:" . $self->{"stat_code_$type"}{$code}{$tmp}{bytes} . ",");
		}
		$dat_file_code->print("\n");
	}
	$dat_file_code->close();
	$self->{"stat_code_$type"} = ();
	$self->{stat_code} = ();

	#### Save mime statistics
	my $dat_file_mime_type = new IO::File;
	$dat_file_mime_type->open(">$self->{Output}/$path/stat_mime_type.dat")
		or die "ERROR: Can't write to file $self->{Output}/$path/stat_mime_type.dat, $!\n";
	foreach my $mime (sort {$a cmp $b} keys %{$self->{"stat_mime_type_$type"}}) {
		$dat_file_mime_type->print("$mime hits=" . $self->{"stat_mime_type_$type"}{$mime}{hits} . ";" .
			"bytes=" . $self->{"stat_mime_type_$type"}{$mime}{bytes} .  "\n");
	}
	$dat_file_mime_type->close();
	$self->{"stat_mime_type_$type"} = ();

}

sub _save_data
{
	my ($self, $year, $month, $day) = @_;

	my $path = join('/', $year, $month, $day);
	$path =~ s/[\/]+$//;

	#### Create directory structure
	if (!-d "$self->{Output}/$year") {
		mkdir("$self->{Output}/$year", 0755) || die "ERROR: can't create directory $self->{Output}/$year, $!\n";
	}
	if ($month && !-d "$self->{Output}/$year/$month") {
		mkdir("$self->{Output}/$year/$month", 0755) || die "ERROR: can't create directory $self->{Output}/$year/$month, $!\n";
	}
	if ($day && !-d "$self->{Output}/$year/$month/$day") {
		mkdir("$self->{Output}/$year/$month/$day", 0755) || die "ERROR: can't create directory $self->{Output}/$year/$month/$day, $!\n";
	}
	print STDERR "Dumping data into $self->{Output}/$path\n" if (!$self->{QuietMode});
	$self->_save_stat($year, $month, $day);

}


sub _read_stat
{
	my ($self, $year, $month, $day) = @_;

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	my $path = join('/',  $year, $month, $day);
	$path =~ s/[\/]+$//;

	#### Read previous client statistics
	my $dat_file_user = new IO::File;
	if ($dat_file_user->open("$self->{Output}/$path/stat_user.dat")) {
		my $i = 1;
		while (my $l = <$dat_file_user>) {
			chomp($l);
			if ($l =~ s/^([^\s]+)\s+hits_$type=([^;]+);bytes_$type=([^;]+);duration_$type=([^;]+);largest_file_size=([^;]*);largest_file_url=(.*)$//) {
				my $id = $1;
				my $hits = $2 || '';
				my $bytes = $3 || '';
				my $duration = $4 || '';
				if ($5 > $self->{"stat_usermax_$type"}{$id}{largest_file_size}) {
					$self->{"stat_usermax_$type"}{$id}{largest_file_size} = $5;
					$self->{"stat_usermax_$type"}{$id}{largest_file_url} = $6;
				}
				$hits =~ s/,$//;	
				$bytes =~ s/,$//;	
				$duration =~ s/,$//;	
				my %hits_tmp = split(/[:,]/, $hits);
				foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
					$self->{"stat_user_$type"}{$id}{$tmp}{hits} += $hits_tmp{$tmp};
				}
				my %bytes_tmp = split(/[:,]/, $bytes);
				foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
					$self->{"stat_user_$type"}{$id}{$tmp}{bytes} += $bytes_tmp{$tmp};
				}
				my %duration_tmp = split(/[:,]/, $duration);
				foreach my $tmp (sort {$a <=> $b} keys %duration_tmp) {
					$self->{"stat_user_$type"}{$id}{$tmp}{duration} += $duration_tmp{$tmp};
				}
			} else {
				print STDERR "ERROR: bad format at line $i into $self->{Output}/$path/stat_user.dat:\n";
				print STDERR "$l\n";
				exit 0;
			}
			$i++;
		}
		$dat_file_user->close();
	}

	#### Read previous url statistics
	if ($self->{UrlReport}) {
		my $dat_file_user_url = new IO::File;
		if ($dat_file_user_url->open("$self->{Output}/$path/stat_user_url.dat")) {
			my $i = 1;
			while (my $l = <$dat_file_user_url>) {
				chomp($l);
				if ($l =~ s/^([^\s]+)\s+hits=(\d+);bytes=(\d+);duration=(\d+);first=([^;]*);last=([^;]*);url=(.*)$//) {
					$self->{"stat_user_url_$type"}{$1}{"$7"}{hits} += $2;
					$self->{"stat_user_url_$type"}{$1}{"$7"}{bytes} += $3;
					$self->{"stat_user_url_$type"}{$1}{"$7"}{duration} += $4;
					$self->{"stat_user_url_$type"}{$1}{"$7"}{firsthit} = $5 if (!$self->{"stat_user_url_$type"}{$1}{"$7"}{firsthit});
					$self->{"stat_user_url_$type"}{$1}{"$7"}{lasthit} = $6;
				} elsif ($l =~ s/^([^\s]+)\s+hits=(\d+);bytes=(\d+);duration=(\d+);url=(.*)$//) {
					$self->{"stat_user_url_$type"}{$1}{"$5"}{hits} += $2;
					$self->{"stat_user_url_$type"}{$1}{"$5"}{bytes} += $3;
					$self->{"stat_user_url_$type"}{$1}{"$5"}{duration} += $4;
				} else {
					print STDERR "ERROR: bad format at line $i into $self->{Output}/$path/stat_user_url.dat\n";
					print STDERR "$l\n";
					exit 0;
				}
				$i++;
			}
			$dat_file_user_url->close();
		}
	}

	#### Read previous network statistics
	my $dat_file_network = new IO::File;
	if ($dat_file_network->open("$self->{Output}/$path/stat_network.dat")) {
		my $i = 1;
		while (my $l = <$dat_file_network>) {
			chomp($l);
			my ($net, $data) = split(/\t/, $l);
			if (!$data) {
				# Assume backward compatibility
				$l =~ s/^(.*)\shits_$type=/hits_$type=/;
				$net = $1;
				$data = $l;
			}
			if ($data =~ s/^hits_$type=([^;]+);bytes_$type=([^;]+);duration_$type=([^;]+);largest_file_size=([^;]*);largest_file_url=(.*)$//) {
				my $hits = $1 || '';
				my $bytes = $2 || '';
				my $duration = $3 || '';
				if ($4 > $self->{"stat_netmax_$type"}{$net}{largest_file_size}) {
					$self->{"stat_netmax_$type"}{$net}{largest_file_size} = $4;
					$self->{"stat_netmax_$type"}{$net}{largest_file_url} = $5;
				}
				$hits =~ s/,$//;	
				$bytes =~ s/,$//;	
				$duration =~ s/,$//;	
				my %hits_tmp = split(/[:,]/, $hits);
				foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
					$self->{"stat_network_$type"}{$net}{$tmp}{hits} += $hits_tmp{$tmp};
				}
				my %bytes_tmp = split(/[:,]/, $bytes);
				foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
					$self->{"stat_network_$type"}{$net}{$tmp}{bytes} += $bytes_tmp{$tmp};
				}
				my %duration_tmp = split(/[:,]/, $duration);
				foreach my $tmp (sort {$a <=> $b} keys %duration_tmp) {
					$self->{"stat_network_$type"}{$net}{$tmp}{duration} += $duration_tmp{$tmp};
				}
			} else {
				print STDERR "ERROR: bad format at line $i into $self->{Output}/$path/stat_network.dat\n";
				print STDERR "$l\n";
				exit 0;
			}
			$i++;
		}
		$dat_file_network->close();
	}

	#### Read previous user per network statistics
	my $dat_file_netuser = new IO::File;
	if ($dat_file_netuser->open("$self->{Output}/$path/stat_netuser.dat")) {
		my $i = 1;
		while (my $l = <$dat_file_netuser>) {
			chomp($l);
			my ($net, $id, $data) = split(/\t/, $l);
			if (!$data) {
				# Assume backward compatibility
				$l =~ s/^(.*)\s([^\s]+)\shits=/hits=/;
				$net = $1;
				$id = $2;
				$data = $l;
			}
			if ($data =~ s/^hits=(\d+);bytes=(\d+);duration=(\d+);largest_file_size=([^;]*);largest_file_url=(.*)$//) {
				$self->{"stat_netuser_$type"}{$net}{$id}{hits} += $2;
				$self->{"stat_netuser_$type"}{$net}{$id}{bytes} += $3;
				$self->{"stat_netuser_$type"}{$net}{$id}{duration} += $4;
				if ($6 > $self->{"stat_netuser_$type"}{$net}{$id}{largest_file_size}) {
					$self->{"stat_netuser_$type"}{$net}{$id}{largest_file_size} = $5;
					$self->{"stat_netuser_$type"}{$net}{$id}{largest_file_url} = $6;
				}
			} else {
				print STDERR "ERROR: bad format at line $i into $self->{Output}/$path/stat_netuser.dat\n";
				print STDERR "$l\n";
				exit 0;
			}
			$i++;
		}
		$dat_file_netuser->close();
	}

	#### Read previous cache statistics
	my $dat_file_code = new IO::File;
	if ($dat_file_code->open("$self->{Output}/$path/stat_code.dat")) {
		my $i = 1;
		while (my $l = <$dat_file_code>) {
			chomp($l);
			if ($l =~ s/^([^\s]+)\s+hits_$type=([^;]+);bytes_$type=([^;]+)$//) {
				my $code = $1;
				my $hits = $2 || '';
				my $bytes = $3 || '';
				$hits =~ s/,$//;	
				$bytes =~ s/,$//;	
				my %hits_tmp = split(/[:,]/, $hits);
				foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
					$self->{"stat_code_$type"}{$code}{$tmp}{hits} += $hits_tmp{$tmp};
				}
				my %bytes_tmp = split(/[:,]/, $bytes);
				foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
					$self->{"stat_code_$type"}{$code}{$tmp}{bytes} += $bytes_tmp{$tmp};
				}
			} else {
				print STDERR "ERROR: bad format at line $i into $self->{Output}/$path/stat_code.dat\n";
				print STDERR "$l\n";
				exit 0;
			}
			$i++;
		}
		$dat_file_code->close();
	}

	#### Read previous mime statistics
	my $dat_file_mime_type = new IO::File;
	if ($dat_file_mime_type->open("$self->{Output}/$path/stat_mime_type.dat")) {
		my $i = 1;
		while (my $l = <$dat_file_mime_type>) {
			chomp($l);
			if ($l =~ s/^([^\s]+)\s+hits=(\d+);bytes=(\d+)//) {
				my $mime = $1;
				$self->{"stat_mime_type_$type"}{$mime}{hits} += $2;
				$self->{"stat_mime_type_$type"}{$mime}{bytes} += $3;
			} else {
				print STDERR "ERROR: bad format at line $i into $self->{Output}/$path/stat_mime_type.dat\n";
				print STDERR "$l\n";
				exit 0;
			}
			$i++;
		}
		$dat_file_mime_type->close();
	}

}

sub _print_header
{
	my ($self, $fileout, $str, $cal) = @_;

	my $now = strftime("%a %b %e %H:%M:%S %Y", localtime);

	print $$fileout qq{
<!DOCTYPE html
	PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
	 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en-US" xml:lang="en-US">
<head>
<meta NAME="robots" CONTENT="noindex,nofollow" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache" />
<meta HTTP-EQUIV="Cache-Control" content="no-cache" />
<meta HTTP-EQUIV="Expires" CONTENT="$now" />
<meta HTTP-EQUIV="Generator" CONTENT="SquidAnalyzer $VERSION" />
<meta HTTP-EQUIV="Date" CONTENT="$now" />
<meta HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8" />
<title>SquidAnalyzer $VERSION Report</title>
<link rel="stylesheet" type="text/css" href="$self->{WebUrl}squidanalyzer.css" media="screen" />
<!-- javascript to sort table -->
<script type="text/javascript" src="$self->{WebUrl}sorttable.js"></script>
</head>
<body text="black" bgcolor="white">
<a name="atop"></a>
<table>
<tr><td>
<div id="logo">
<a href="$self->{WebUrl}"><img src="$self->{WebUrl}logo-squidanalyzer.png" title="SquidAnalyzer $VERSION" border="0"></a><br>
<i><b>$Translate{'Generation'} $now.</b></i>
</div>
</td>
<td align="right" valign="top">
$str
<br />
$cal
</td>
</tr>
</table>
};

}


sub _print_footer
{
	my ($self, $fileout) = @_;

	if ($self->{FooterFile}) {
		$self->{FooterFile} =~ s/\%VERSION\%/v$VERSION/gs;
		print $$fileout qq{ $self->{FooterFile} };
	} else {
		print $$fileout qq{
<hr>
This file was generated by <a href="http://squidanalyzer.darold.net/">SquidAnalyzer v$VERSION</a>
};
	}
	print $$fileout qq{
</body>
</html>
};

}

sub buildHTML
{
	my ($self, $outdir) = @_;

	$outdir ||= $self->{Output};

	print STDERR "Building HTML output into $outdir\n" if (!$self->{QuietMode});

	# Load history data for incremental scan
	my $old_year = 0;
	my $old_month = 0;
	my $old_day = 0;
	if ($self->{history_time}) {
		$old_year = (localtime($self->{history_time}))[5]+1900;
		$old_month = (localtime($self->{history_time}))[4]+1;
		$old_month = "0$old_month" if ($old_month < 10);
		$old_day = (localtime($self->{history_time}))[3];
		$old_day = "0$old_day" if ($old_day < 10);
	}

	# Generate all HTML output
	opendir(DIR, $outdir) || die "Error: can't opendir $outdir: $!";
	my @years = grep { /^\d{4}$/ && -d "$outdir/$_"} readdir(DIR);
	closedir DIR;
	foreach my $y (sort {$a <=> $b} @years) {
		next if ($y < $old_year);
		opendir(DIR, "$outdir/$y") || die "Error: can't opendir $outdir/$y: $!";
		my @months = grep { /^\d{2}$/ && -d "$outdir/$y/$_"} readdir(DIR);
		closedir DIR;
		foreach my $m (sort {$a <=> $b} @months) {
			next if ($m < $old_month);
			opendir(DIR, "$outdir/$y/$m") || die "Error: can't opendir $outdir/$y/$m: $!";
			my @days = grep { /^\d{2}$/ && -d "$outdir/$y/$m/$_"} readdir(DIR);
			closedir DIR;
			foreach my $d (sort {$a <=> $b} @days) {
				next if ($d < $old_day);
				print STDERR "Generating daily statistics for day $y-$m-$d\n" if (!$self->{QuietMode});
				$self->gen_html_output($outdir, $y, $m, $d);
			}
			print STDERR "Generating monthly statistics for month $y-$m\n" if (!$self->{QuietMode});
			$self->gen_html_output($outdir, $y, $m);
		}
		print STDERR "Generating yearly statistics for year $y\n" if (!$self->{QuietMode});
		$self->gen_html_output($outdir, $y);
	}

	$self->_gen_summary($outdir);
}

sub gen_html_output
{
	my ($self, $outdir, $year, $month, $day) = @_;

	my $dir = "$outdir";
	if ($year) {
		$dir .= "/$year";
	}
	if ($month) {
		$dir .= "/$month";
	}
	if ($day) {
		$dir .= "/$day";
	}
	my $stat_date = $self->set_date($year, $month, $day);

	print STDERR "\tUser statistics in $dir...\n" if (!$self->{QuietMode});
	my $nuser = $self->_print_user_stat($dir, $year, $month, $day);
	print STDERR "\tMime type statistics in $dir...\n" if (!$self->{QuietMode});
	$self->_print_mime_stat($dir, $year, $month, $day);
	print STDERR "\tNetwork statistics in $dir...\n" if (!$self->{QuietMode});
	$self->_print_network_stat($dir, $year, $month, $day);
	my $nurl = 0;
	my $ndomain = 0;
	if ($self->{UrlReport}) {
		print STDERR "\tTop URL statistics in $dir...\n" if (!$self->{QuietMode});
		$nurl = $self->_print_top_url_stat($dir, $year, $month, $day);
		print STDERR "\tTop domain statistics in $dir...\n" if (!$self->{QuietMode});
		$ndomain = $self->_print_top_domain_stat($dir, $year, $month, $day);
	}
	print STDERR "\tCache statistics in $dir...\n" if (!$self->{QuietMode});
	$self->_print_cache_stat($dir, $year, $month, $day, $nuser, $nurl, $ndomain);

	return ($nuser, $nurl, $ndomain);

}

sub parse_duration
{
	my ($secondes) = @_;

	my $hours = int($secondes/3600);
	$hours = "0$hours" if ($hours < 10);
	$secondes = $secondes - ($hours*3600);
	my $minutes = int($secondes/60);
	$minutes = "0$minutes" if ($minutes < 10);
	$secondes = $secondes - ($minutes*60);
	$secondes = "0$secondes" if ($secondes < 10);

	return "$hours:$minutes:$secondes";
}

sub _print_cache_stat
{
	my ($self, $outdir, $year, $month, $day, $nuser, $nurl, $ndomain) = @_;

	my $stat_date = $self->set_date($year, $month, $day);

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_code.dat") || return;
	my %code_stat = ();
	my %detail_code_stat = ();
	while (my $l = <$infile>) {
		chomp($l);
		my ($code, $data) = split(/\s/, $l);
		$data =~ /hits_$type=([^;]+);bytes_$type=([^;]+)/;
		my $hits = $1 || '';
		my $bytes = $2 || '';
		$hits =~ s/,$//;
		$bytes =~ s/,$//;
		my %hits_tmp = split(/[:,]/, $hits);
		foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
			$detail_code_stat{$code}{$tmp}{request} = $hits_tmp{$tmp};
			$code_stat{$code}{request} += $hits_tmp{$tmp};
		}
		my %bytes_tmp = split(/[:,]/, $bytes);
		foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
			$detail_code_stat{$code}{$tmp}{bytes} = $bytes_tmp{$tmp};
			$code_stat{$code}{bytes} += $bytes_tmp{$tmp};
		}
	}
	$infile->close();
	my $total_request =  $code_stat{HIT}{request} + $code_stat{MISS}{request};
	my $total_bytes = $code_stat{HIT}{bytes} + $code_stat{MISS}{bytes};

	my $file = $outdir . '/index.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	my $cal = $self->_get_calendar($stat_date, $type, $outdir);
	$self->_print_header(\$out, $self->{menu}, $cal);

	# Print title and calendar view
	print $out $self->_print_title($Translate{'Cache_title'}, $stat_date);

	my $total_cost = sprintf("%2.2f", int($total_bytes/1000000) * $self->{CostPrice});
	my $comma_bytes = &format_bytes($total_bytes);
	my $hit_bytes = &format_bytes($code_stat{HIT}{bytes});
	my $miss_bytes = &format_bytes($code_stat{MISS}{bytes});
	my $colspn = 5;
	$colspn = 6 if ($self->{CostPrice});
	print $out qq{<table><tr><td><img src="code_request.png"></td><td><img src="code_bytes.png"></td></tr></table>};
	print $out qq{
<div id="stata">
<table>
<tr>
<th colspan="2">$Translate{'Requests'}</th>
<th colspan="2">$Translate{'Bytes'}</th>
<th colspan="$colspn">$Translate{'Total'}</th>
</tr>
<tr>
<th>$Translate{'Hit'}</th>
<th>$Translate{'Miss'}</th>
<th>$Translate{'Hit'}</th>
<th>$Translate{'Miss'}</th>
<th>$Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th>$Translate{'Users'}</th>
<th>$Translate{'Sites'}</th>
<th>$Translate{'Domains'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
</tr>
<tr>
<td>$code_stat{HIT}{request}</td>
<td>$code_stat{MISS}{request}</td>
<td>$hit_bytes</td>
<td>$miss_bytes</td>
<td>$total_request</td>
<td>$comma_bytes</td>
<td>$nuser</td>
<td>$nurl</td>
<td>$ndomain</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
	print $out qq{
</tr>
</table>
</div>
<pre>
	<b>$Translate{'Hit'}:</b> $Translate{'Hit_help'}
	<b>$Translate{'Miss'}:</b> $Translate{'Miss_help'}
	<b>$Translate{'Users'}:</b> $Translate{'Users_help'}
	<b>$Translate{'Sites'}:</b> $Translate{'Sites_help'}
	<b>$Translate{'Domains'}:</b> $Translate{'Domains_help'}
};
	print $out qq{
	<b>$Translate{'Cost'}:</b> $Translate{'Cost_help'} $self->{CostPrice} $self->{Currency}
} if ($self->{CostPrice});
	print $out qq{
</pre>
};

	%code_stat = ();
	$self->_print_footer(\$out);
	$out->close();

	my $last = '23';
	my $first = '00';
	my $title = $Translate{'Hourly'} || 'Hourly';
	my $unit = $Translate{'Hours'} || 'Hours';
	if ($type eq 'day') {
		$last = '31';
		$first = '01';
		$title = $Translate{'Daily'} || 'Daily';
		$unit = $Translate{'Days'} || 'Days';
	} elsif ($type eq 'month') {
		$last = '12';
		$first = '01';
		$title = $Translate{'Monthly'} || 'Monthly';
		$unit = $Translate{'Months'} || 'Months';
	}
	my @labels = ();
	my @hit = ();
	my @miss = ();
	my @total = ();
	for ("$first" .. "$last") {
		push(@labels, "$_");
		my $tot = 0;
		if (exists $detail_code_stat{HIT}{$_}{request}) {
			push(@hit, $detail_code_stat{HIT}{$_}{request});
			$tot += $detail_code_stat{HIT}{$_}{request};
		} else {
			push(@hit, 0);
		}
		if (exists $detail_code_stat{MISS}{$_}{request}) {
			push(@miss, $detail_code_stat{MISS}{$_}{request});
			$tot += $detail_code_stat{MISS}{$_}{request};
		} else {
			push(@miss, 0);
		}
		push(@total, $tot);
		delete $detail_code_stat{HIT}{$_}{request};
		delete $detail_code_stat{MISS}{$_}{request};
	}
	if ($type eq 'month') {
		@labels = (
			$Translate{'01'}, $Translate{'02'}, $Translate{'03'}, $Translate{'04'},
			$Translate{'05'}, $Translate{'06'}, $Translate{'07'}, $Translate{'08'},
			$Translate{'09'}, $Translate{'10'}, $Translate{'11'}, $Translate{'12'}
		);
	}
	my @legends = ($Translate{'Hit_graph'}, $Translate{'Miss_graph'}, $Translate{'Total_graph'});
	my @data = (
	    [@labels],
	    [@hit],
	    [@miss],
	    [@total]
	);
	my $t1 = $Translate{'Graph_cache_hit_title'};
	$t1 =~ s/\%s/$title/;
	local (*IMG) = undef;
	open(IMG, ">$outdir/code_request.png") or die "Error: can't create file $outdir/code_request.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Requests_graph'} || 'Requests'));
	close(IMG);

	@hit = ();
	@miss = ();
	@total = ();
	for ("$first" .. "$last") {
		my $tot = 0;
		if (exists $detail_code_stat{HIT}{$_}{bytes}) {
			push(@hit, int($detail_code_stat{HIT}{$_}{bytes}/1000000));
			$tot += $detail_code_stat{HIT}{$_}{bytes};
		} else {
			push(@hit, 0);
		}
		if (exists $detail_code_stat{MISS}{$_}{bytes}) {
			push(@miss, int($detail_code_stat{MISS}{$_}{bytes}/1000000));
			$tot += $detail_code_stat{MISS}{$_}{bytes};
		} else {
			push(@miss, 0);
		}
		push(@total, int($tot/1000000));
	}
	%detail_code_stat = ();
	@data = (
	    [@labels],
	    [@hit],
	    [@miss],
	    [@total]
	);
	$t1 = $Translate{'Graph_cache_byte_title'};
	$t1 =~ s/\%s/$title/;
	local (*IMG) = undef;
	open(IMG, ">$outdir/code_bytes.png") or die "Error: can't create file $outdir/code_bytes.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Megabytes_graph'} || $Translate{'Megabytes'}));
	close(IMG);

}


sub _print_mime_stat
{
	my ($self, $outdir, $year, $month, $day) = @_;

	my $stat_date = $self->set_date($year, $month, $day);

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_mime_type.dat") || return;
	my %mime_stat = ();
	my $total_count = 0;
	my $total_bytes = 0;
	while(my $l = <$infile>) {
		chomp($l);
		my ($code, $data) = split(/\s/, $l);
		$data =~ /hits=(\d+);bytes=(\d+)/;
		$mime_stat{$code}{hits} = $1;
		$mime_stat{$code}{bytes} = $2;
		$total_count += $1;
		$total_bytes += $2;
	}
	$infile->close();

	my $ntype = scalar keys %mime_stat;

	my $file = $outdir . '/mime_type.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	my $cal = $self->_get_calendar($stat_date, $type, $outdir);
	$self->_print_header(\$out, $self->{menu}, $cal);
	# Print title and calendar view
	print $out $self->_print_title($Translate{'Mime_title'}, $stat_date);

	print $out "<b>$Translate{'Mime_number'}:</b> $ntype<br>\n";
	print $out qq{
<div id="stata">
<table class="sortable" cellpadding=1 cellspacing=1 align=center>
<thead>
<tr>
<th nowrap>$Translate{'Mime_link'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
</tr>
</thead>
};
	foreach (sort { $mime_stat{$b}{"$self->{OrderMime}"} <=> $mime_stat{$a}{"$self->{OrderMime}"} } keys %mime_stat) {
		my $c_percent = '0.0';
		$c_percent = sprintf("%2.2f", ($mime_stat{$_}{hits}/$total_count) * 100) if ($total_count);
		my $b_percent = '0.0';
		$b_percent = sprintf("%2.2f", ($mime_stat{$_}{bytes}/$total_bytes) * 100) if ($total_bytes);
		my $total_cost = sprintf("%2.2f", int($mime_stat{$_}{bytes}/1000000) * $self->{CostPrice});
		my $comma_bytes = &format_bytes($mime_stat{$_}{bytes});
		print $out qq{
<tr align=right>
<td align=left>$_</td>
<td>$mime_stat{$_}{hits}</td>
<td>$c_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
	print $out qq{
</tr>};
	}
	print $out qq{
</table>
</div>
};

	print $out qq{
<div id="uplink">
<table align=center>
<tr>
<th><a href="#atop">[ $Translate{'Up_link'} ]</a></th>
</tr>
</table>
</div>
};
	$self->_print_footer(\$out);
	$out->close();

}

sub _print_network_stat
{
	my ($self, $outdir, $year, $month, $day) = @_;

	my $stat_date = $self->set_date($year, $month, $day);

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_network.dat") || return;
	my %network_stat = ();
	my %detail_network_stat = ();
	my %total_net_detail = ();
	my $total_hit = 0;
	my $total_bytes = 0;
	my $total_duration = 0;
	while (my $l = <$infile>) {
		chomp($l);
		my ($network, $data) = split(/\t/, $l);
		if (!$data) {
			# Assume backward compatibility
			$l =~ s/^(.*)\shits_$type=/hits_$type=/;
			$network = $1;
			$data = $l;
		}
		$data =~ /^hits_$type=([^;]+);bytes_$type=([^;]+);duration_$type=([^;]+);largest_file_size=([^;]*);largest_file_url=(.*)/;
		my $hits = $1 || '';
		my $bytes = $2 || '';
		my $duration = $3 || '';
		$network_stat{$network}{largest_file} = $4;
		$network_stat{$network}{url} = $5;
		$hits =~ s/,$//;	
		$bytes =~ s/,$//;	
		$duration =~ s/,$//;	
		my %hits_tmp = split(/[:,]/, $hits);
		foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
			$detail_network_stat{$network}{$tmp}{hits} = $hits_tmp{$tmp};
			$total_net_detail{$tmp}{hits} += $hits_tmp{$tmp};
			$network_stat{$network}{hits} += $hits_tmp{$tmp};
			$total_hit += $hits_tmp{$tmp};
		}
		my %bytes_tmp = split(/[:,]/, $bytes);
		foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
			$detail_network_stat{$network}{$tmp}{bytes} = $bytes_tmp{$tmp};
			$total_net_detail{$tmp}{bytes} += $bytes_tmp{$tmp};
			$network_stat{$network}{bytes} += $bytes_tmp{$tmp};
			$total_bytes += $bytes_tmp{$tmp};
		}
		my %duration_tmp = split(/[:,]/, $duration);
		foreach my $tmp (sort {$a <=> $b} keys %duration_tmp) {
			$detail_network_stat{$network}{$tmp}{duration} = $duration_tmp{$tmp};
			$total_net_detail{$tmp}{duration} += $duration_tmp{$tmp};
			$network_stat{$network}{duration} += $duration_tmp{$tmp};
			$total_duration += $duration_tmp{$tmp};
		}
	}
	$infile->close();
	my $nnet = scalar keys %network_stat;

	my $file = $outdir . '/network.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	my $cal = $self->_get_calendar($stat_date, $type, $outdir);
	$self->_print_header(\$out, $self->{menu}, $cal);
	print $out $self->_print_title($Translate{'Network_title'}, $stat_date);
	print $out qq{<table><tr><td><img src="network_hits.png"></td><td><img src="network_bytes.png"></td></tr></table>};
	print $out "<b>$Translate{'Network_number'}:</b> $nnet<br>\n";
	print $out qq{
<div id="stata">
<table class="sortable" cellpadding=1 cellspacing=1 align=center>
<thead>
<tr>
<th>$Translate{'Network_link'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
<th>$Translate{'Duration'}</th>
<th nowrap>% $Translate{'Time'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
<th nowrap>$Translate{'Users'}</th>
<th>$Translate{'Largest'}</th>
<th>$Translate{'Url'}</th>
</tr>
</thead>
};
	if (!-d "$outdir/networks") {
		mkdir("$outdir/networks", 0755) || return;
	}
	my $last = '23';
	my $first = '00';
	my $title = $Translate{'Hourly'} || 'Hourly';
	my $unit = $Translate{'Hours'} || 'Hours';
	if ($type eq 'day') {
		$last = '31';
		$first = '01';
		$title = $Translate{'Daily'} || 'Daily';
		$unit = $Translate{'Days'} || 'Days';
	} elsif ($type eq 'month') {
		$last = '12';
		$first = '01';
		$title = $Translate{'Monthly'} || 'Monthly';
		$unit = $Translate{'Months'} || 'Months';
	}
	foreach my $net (sort { $network_stat{$b}{"$self->{OrderNetwork}"} <=> $network_stat{$a}{"$self->{OrderNetwork}"} } keys %network_stat) {
		my $h_percent = '0.0';
		$h_percent = sprintf("%2.2f", ($network_stat{$net}{hits}/$total_hit) * 100) if ($total_hit);
		my $b_percent = '0.0';
		$b_percent = sprintf("%2.2f", ($network_stat{$net}{bytes}/$total_bytes) * 100) if ($total_bytes);
		my $d_percent = '0.0';
		$d_percent = sprintf("%2.2f", ($network_stat{$net}{duration}/$total_duration) * 100) if ($total_duration);
		$network_stat{$net}{duration} = &parse_duration(int($network_stat{$net}{duration}/1000));
		my $total_cost = sprintf("%2.2f", int($network_stat{$net}{bytes}/1000000) * $self->{CostPrice});
		my $show = $net;
		if ($net =~ /^\d+\.\d+\.\d+/) {
			$show .= ".0";
			foreach my $n (keys %{$self->{NetworkAlias}}) {
				if ($show =~ /$self->{NetworkAlias}->{$n}/) {
					$show = $n;
					last;
				}
			}
		}
		my $comma_bytes = &format_bytes($network_stat{$net}{bytes});
		print $out qq{
<tr align=right>
<td align=left nowrap><a href="networks/$net/$net.html">$show</a></td>
<td>$network_stat{$net}{hits}</td>
<td>$h_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
<td>$network_stat{$net}{duration}</td>
<td>$d_percent</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});

		if (!-d "$outdir/networks/$net") {
			mkdir("$outdir/networks/$net", 0755) || return;
		}
		my $outnet = new IO::File;
		$outnet->open(">$outdir/networks/$net/$net.html") || return;
		# Print the HTML header
		my $cal = $self->_get_calendar($stat_date, $type, $outdir, '../../');
		$self->_print_header(\$outnet, $self->{menu2}, $cal);
		print $outnet $self->_print_title("$Translate{'Network_title'} $show -", $stat_date);
		print $outnet qq{<table><tr><td><img src="network_hits.png"></td><td><img src="network_bytes.png"></td></tr></table>};
		my $retuser = $self->_print_netuser_stat($outdir, \$outnet, $net);
		print $out qq{
<td>$retuser</td>
<td>$network_stat{$net}{largest_file}</td>
<td align=left>$network_stat{$net}{url}</td>
</tr>
};
		print $outnet qq{
<div id="uplink">
<table align=center>
<tr>
<th><a href="#atop">[ $Translate{'Up_link'} ]</a></th>
</tr>
</table>
</div>
};
		$self->_print_footer(\$outnet);
		$outnet->close();

		my @labels = ();
		my @hits = ();
		my @bytes = ();
		for ("$first" .. "$last") {
			push(@labels, "$_");
			if (exists $detail_network_stat{$net}{$_}{hits}) {
				push(@hits, $detail_network_stat{$net}{$_}{hits});
			} else {
				push(@hits, 0);
			}
			if (exists $detail_network_stat{$net}{$_}{bytes}) {
				push(@bytes, int($detail_network_stat{$net}{$_}{bytes}/1000000));
			} else {
				push(@bytes, 0);
			}
		}
		delete $detail_network_stat{$net};
		if ($type eq 'month') {
			@labels = (
				$Translate{'01'}, $Translate{'02'}, $Translate{'03'}, $Translate{'04'},
				$Translate{'05'}, $Translate{'06'}, $Translate{'07'}, $Translate{'08'},
				$Translate{'09'}, $Translate{'10'}, $Translate{'11'}, $Translate{'12'}
			);
		}

		my @legends = ();
		my @data = (
		    [@labels],
		    [@hits]
		);
		my $t1 = $Translate{'Graph_cache_hit_title'};
		$t1 =~ s/\%s/$title $show/;
		local (*IMG) = undef;
		open(IMG, ">$outdir/networks/$net/network_hits.png") or die "Error: can't create file $outdir/networks/$net/network_hits.png, $!\n";
		binmode IMG;
		print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Requests_graph'} || 'Requests'));
		close(IMG);

		@legends = ();
		@data = (
		    [@labels],
		    [@bytes]
		);
		$t1 = $Translate{'Graph_cache_byte_title'};
		$t1 =~ s/\%s/$title $show/;
		local (*IMG) = undef;
		open(IMG, ">$outdir/networks/$net/network_bytes.png") or die "Error: can't create file $outdir/networks/$net/network_bytes.png, $!\n";
		binmode IMG;
		print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Megabytes_graph'} || $Translate{'Megabytes'}));
		close(IMG);
		delete $network_stat{$net};
	}
	print $out "</table>\n</div>\n";

	print $out qq{
<div id="uplink">
<table align=center>
<tr>
<th><a href="#atop">[ $Translate{'Up_link'} ]</a></th>
</tr>
</table>
</div>
};
	$self->_print_footer(\$out);
	$out->close();

	my @labels = ();
	my @hits = ();
	my @bytes = ();
	for ("$first" .. "$last") {
		push(@labels, "$_");
		if (exists $total_net_detail{$_}{hits}) {
			push(@hits, $total_net_detail{$_}{hits});
		} else {
			push(@hits, 0);
		}
		if (exists $total_net_detail{$_}{bytes}) {
			push(@bytes, int($total_net_detail{$_}{bytes}/1000000));
		} else {
			push(@bytes, 0);
		}
	}
	%total_net_detail = ();
	if ($type eq 'month') {
		@labels = (
			$Translate{'01'}, $Translate{'02'}, $Translate{'03'}, $Translate{'04'},
			$Translate{'05'}, $Translate{'06'}, $Translate{'07'}, $Translate{'08'},
			$Translate{'09'}, $Translate{'10'}, $Translate{'11'}, $Translate{'12'}
		);
	}

	my @legends = ();
	my @data = (
	    [@labels],
	    [@hits]
	);
	my $t1 = $Translate{'Graph_cache_hit_title'};
	$t1 =~ s/\%s/$title/;
	local (*IMG) = undef;
	open(IMG, ">$outdir/network_hits.png") or die "Error: can't create file $outdir/network_hits.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Requests_graph'} || 'Requests'));
	close(IMG);

	@legends = ();
	@data = (
	    [@labels],
	    [@bytes]
	);
	$t1 = $Translate{'Graph_cache_byte_title'};
	$t1 =~ s/\%s/$title/;
	local (*IMG) = undef;
	open(IMG, ">$outdir/network_bytes.png") or die "Error: can't create file $outdir/network_bytes.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Megabytes_graph'} || $Translate{'Megabytes'}));
	close(IMG);

}

sub _print_user_stat
{
	my ($self, $outdir, $year, $month, $day) = @_;

	my $stat_date = $self->set_date($year, $month, $day);

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_user.dat") || return;
	my %user_stat = ();
	my %detail_user_stat = ();
	my %total_user_detail = ();
        my $total_hit = 0;
        my $total_bytes = 0;
        my $total_duration = 0;
	while(my $l = <$infile>) {
		chomp($l);
		my ($user, $data) = split(/\s/, $l);
		$data =~ /hits_$type=([^;]+);bytes_$type=([^;]+);duration_$type=([^;]+);largest_file_size=([^;]*);largest_file_url=(.*)/;
		my $hits = $1 || '';
		my $bytes = $2 || '';
		my $duration = $3 || '';
		$user_stat{$user}{largest_file} = $4;
		$user_stat{$user}{url} = $5;
		$hits =~ s/,$//;
		$bytes =~ s/,$//;
		$duration =~ s/,$//;
		my %hits_tmp = split(/[:,]/, $hits);
		foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
			$detail_user_stat{$user}{$tmp}{hits} = $hits_tmp{$tmp};
			$total_user_detail{$tmp}{hits} += $hits_tmp{$tmp};
			$user_stat{$user}{hits} += $hits_tmp{$tmp};
			$total_hit += $hits_tmp{$tmp};
		}
		my %bytes_tmp = split(/[:,]/, $bytes);
		foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
			$detail_user_stat{$user}{$tmp}{bytes} = $bytes_tmp{$tmp};
			$total_user_detail{$tmp}{bytes} += $bytes_tmp{$tmp};
			$user_stat{$user}{bytes} += $bytes_tmp{$tmp};
			$total_bytes += $bytes_tmp{$tmp};
		}
		my %duration_tmp = split(/[:,]/, $duration);
		foreach my $tmp (sort {$a <=> $b} keys %duration_tmp) {
			$detail_user_stat{$user}{$tmp}{duration} = $duration_tmp{$tmp};
			$total_user_detail{$tmp}{duration} += $duration_tmp{$tmp};
			$user_stat{$user}{duration} += $duration_tmp{$tmp};
			$total_duration += $duration_tmp{$tmp};
		}
	}
	$infile->close();
	my $nuser = scalar keys %user_stat;

	my $file = $outdir . '/user.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	my $cal = $self->_get_calendar($stat_date, $type, $outdir);
	$self->_print_header(\$out, $self->{menu}, $cal);
	print $out $self->_print_title($Translate{'User_title'}, $stat_date);
	print $out qq{<table><tr><td><img src="user_hits.png"></td><td><img src="user_bytes.png"></td></tr></table>};
	print $out "<b>$Translate{'User_number'}:</b> $nuser<br>\n";
	print $out qq{
<div id="stata">
<table class="sortable">
<thead>
<tr align="center">
<th>$Translate{'Users'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
<th>$Translate{'Duration'}</th>
<th nowrap>% $Translate{'Time'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
<th>$Translate{'Largest'}</th>
<th>$Translate{'Url'}</th>
</tr>
</thead>
};
	if (!-d "$outdir/users") {
		mkdir("$outdir/users", 0755) || return;
	}

	my $last = '23';
	my $first = '00';
	my $title = $Translate{'Hourly'} || 'Hourly';
	my $unit = $Translate{'Hours'} || 'Hours';
	if ($type eq 'day') {
		$last = '31';
		$first = '01';
		$title = $Translate{'Daily'} || 'Daily';
		$unit = $Translate{'Days'} || 'Days';
	} elsif ($type eq 'month') {
		$last = '12';
		$first = '01';
		$title = $Translate{'Monthly'} || 'Monthly';
		$unit = $Translate{'Months'} || 'Months';
	}
	foreach my $usr (sort { $user_stat{$b}{"$self->{OrderUser}"} <=> $user_stat{$a}{"$self->{OrderUser}"} } keys %user_stat) {
		my $h_percent = '0.0';
		$h_percent = sprintf("%2.2f", ($user_stat{$usr}{hits}/$total_hit) * 100) if ($total_hit);
		my $b_percent = '0.0';
		$b_percent = sprintf("%2.2f", ($user_stat{$usr}{bytes}/$total_bytes) * 100) if ($total_bytes);
		my $d_percent = '0.0';
		$d_percent = sprintf("%2.2f", ($user_stat{$usr}{duration}/$total_duration) * 100) if ($total_duration);
		$user_stat{$usr}{duration} = &parse_duration(int($user_stat{$usr}{duration}/1000));
		my $total_cost = sprintf("%2.2f", int($user_stat{$usr}{bytes}/1000000) * $self->{CostPrice});
		my $show = $usr;
		foreach my $u (keys %{$self->{UserAlias}}) {
			if ( grep($usr =~ /^$_$/,  @{$self->{UserAlias}->{$u}}) ) {
				$show = $u;
				last;
			}
		}
		my $url = &escape($usr);
		my $comma_bytes = &format_bytes($user_stat{$usr}{bytes});
		if ($self->{UrlReport}) {
			print $out qq{
<tr align=right>
<td align=left nowrap><a href="users/$url/$url.html">$show</a></td>
};
		} else {
			print $out qq{
<tr align=right>
<td align=left nowrap>$show</td>
};
		}
		print $out qq{
<td>$user_stat{$usr}{hits}</td>
<td>$h_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
<td>$user_stat{$usr}{duration}</td>
<td>$d_percent</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
	print $out qq{
<td>$user_stat{$usr}{largest_file}</td>
<td align=left>$user_stat{$usr}{url}</td>
</tr>};

		if (!-d "$outdir/users/$url") {
			mkdir("$outdir/users/$url", 0755) || return;
		}
		my $outusr = new IO::File;
		$outusr->open(">$outdir/users/$url/$url.html") || return;
		# Print the HTML header
		my $cal = $self->_get_calendar($stat_date, $type, $outdir, '../../');
		$self->_print_header(\$outusr, $self->{menu2}, $cal);
		print $outusr $self->_print_title("$Translate{'User_title'} $usr -", $stat_date);
		print $outusr qq{<table><tr><td><img src="user_hits.png"></td><td><img src="user_bytes.png"></td></tr></table>};
		if ($self->{UrlReport}) {
			$self->_print_user_detail(\$outusr, $outdir, $usr);
		}
		$self->_print_footer(\$outusr);
		$outusr->close();

		my @labels = ();
		my @hits = ();
		my @bytes = ();
		for ("$first" .. "$last") {
			push(@labels, "$_");
			if (exists $detail_user_stat{$usr}{$_}{hits}) {
				push(@hits, $detail_user_stat{$usr}{$_}{hits});
			} else {
				push(@hits, 0);
			}
			if (exists $detail_user_stat{$usr}{$_}{bytes}) {
				push(@bytes, int($detail_user_stat{$usr}{$_}{bytes}/1000000));
			} else {
				push(@bytes, 0);
			}
		}
		delete $detail_user_stat{$usr};
		if ($type eq 'month') {
			@labels = (
				$Translate{'01'}, $Translate{'02'}, $Translate{'03'}, $Translate{'04'},
				$Translate{'05'}, $Translate{'06'}, $Translate{'07'}, $Translate{'08'},
				$Translate{'09'}, $Translate{'10'}, $Translate{'11'}, $Translate{'12'}
			);
		}

		my @legends = ();
		my @data = (
		    [@labels],
		    [@hits]
		);
		my $t1 = $Translate{'Graph_cache_hit_title'};
		$t1 =~ s/\%s/$title $show/;
		local (*IMG) = undef;
		open(IMG, ">$outdir/users/$url/user_hits.png") or die "Error: can't create file $outdir/users/$url/user_hits.png, $!\n";
		binmode IMG;
		print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Requests_graph'} || 'Requests'));
		close(IMG);

		@legends = ();
		@data = (
		    [@labels],
		    [@bytes]
		);
		$t1 = $Translate{'Graph_cache_byte_title'};
		$t1 =~ s/\%s/$title $show/;
		local (*IMG) = undef;
		open(IMG, ">$outdir/users/$url/user_bytes.png") or die "Error: can't create file $outdir/users/$url/user_bytes.png, $!\n";
		binmode IMG;
		print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Megabytes_graph'} || $Translate{'Megabytes'}));
		close(IMG);
		delete $user_stat{$usr};
	}
	print $out qq{
</table>
</div>
};

	print $out qq{
<div id="uplink">
<table align=center>
<tr>
<th><a href="#atop">[ $Translate{'Up_link'} ]</a></th>
</tr>
</table>
</div>
};
	$self->_print_footer(\$out);
	$out->close();

	my @labels = ();
	my @hits = ();
	my @bytes = ();
	for ("$first" .. "$last") {
		push(@labels, "$_");
		if (exists $total_user_detail{$_}{hits}) {
			push(@hits, $total_user_detail{$_}{hits});
		} else {
			push(@hits, 0);
		}
		if (exists $total_user_detail{$_}{bytes}) {
			push(@bytes, int($total_user_detail{$_}{bytes}/1000000));
		} else {
			push(@bytes, 0);
		}
	}
	%total_user_detail = ();
	if ($type eq 'month') {
		@labels = (
			$Translate{'01'}, $Translate{'02'},
			$Translate{'03'}, $Translate{'04'},
			$Translate{'05'}, $Translate{'06'},
			$Translate{'07'}, $Translate{'08'},
			$Translate{'09'}, $Translate{'10'},
			$Translate{'11'}, $Translate{'12'}
		);
	}

	my @legends = ();
	my @data = (
	    [@labels],
	    [@hits]
	);
	my $t1 = $Translate{'Graph_cache_hit_title'};
	$t1 =~ s/\%s/$title/;
	local (*IMG) = undef;
	open(IMG, ">$outdir/user_hits.png") or die "Error: can't create file $outdir/user_hits.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Requests_graph'} || 'Requests'));
	close(IMG);

	@legends = ();
	@data = (
	    [@labels],
	    [@bytes]
	);
	$t1 = $Translate{'Graph_cache_byte_title'};
	$t1 =~ s/\%s/$title/;
	local (*IMG) = undef;
	open(IMG, ">$outdir/user_bytes.png") or die "Error: can't create file $outdir/user_bytes.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$t1 $stat_date",'x_label' => $unit, 'y_label' => $Translate{'Megabytes_graph'} || $Translate{'Megabytes'}));
	close(IMG);

	return $nuser;
}

sub _print_netuser_stat
{
	my ($self, $outdir, $out, $usrnet) = @_;

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_netuser.dat") || return;
	my %netuser_stat = ();
	my $total_hit = 0;
	my $total_bytes = 0;
	my $total_duration = 0;
	while(my $l = <$infile>) {
		chomp($l);
		my ($network, $user, $data) = split(/\t/, $l);
		if (!$data) {
			# Assume backward compatibility
			$l =~ s/^(.*)\s([^\s]+)\shits=/hits=/;
			$network = $1;
			$user = $2;
			$data = $l;
		}
		next if ($network ne $usrnet);
		$data =~ /^hits=(\d+);bytes=(\d+);duration=(\d+);largest_file_size=([^;]*);largest_file_url=(.*)/;
		$netuser_stat{$user}{hits} = $1;
		$netuser_stat{$user}{bytes} = $2;
		$netuser_stat{$user}{duration} = $3;
		$netuser_stat{$user}{largest_file} = $4;
		$total_hit += $1;
		$total_bytes += $2;
		$total_duration += $3;
		$netuser_stat{$user}{url} = $5;
	}
	$infile->close();
	my $nuser = scalar keys %netuser_stat;

	print $$out qq{
<b>$Translate{'User_number'}:</b> $nuser<br>
};
	print $$out qq{
<div id="stata">
<table class="sortable">
<thead>
<tr>
<th>$Translate{'Users'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
<th>$Translate{'Duration'}</th>
<th nowrap>% $Translate{'Time'}</th>
};
	print $$out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $$out qq{
<th>$Translate{'Largest'}</th>
<th>$Translate{'Url'}</th>
</tr>
</thead>
};
	foreach my $usr (sort { $netuser_stat{$b}{"$self->{OrderUser}"} <=> $netuser_stat{$a}{"$self->{OrderUser}"} } keys %netuser_stat) {
		my $h_percent = '0.0';
		$h_percent = sprintf("%2.2f", ($netuser_stat{$usr}{hits}/$total_hit) * 100) if ($total_hit);
		my $b_percent = '0.0';
		$b_percent = sprintf("%2.2f", ($netuser_stat{$usr}{bytes}/$total_bytes) * 100) if ($total_bytes);
		my $d_percent = '0.0';
		$d_percent = sprintf("%2.2f", ($netuser_stat{$usr}{duration}/$total_duration) * 100) if ($total_duration);
		$netuser_stat{$usr}{duration} = &parse_duration(int($netuser_stat{$usr}{duration}/1000));
		my $total_cost = sprintf("%2.2f", int($netuser_stat{$usr}{bytes}/1000000) * $self->{CostPrice});
		my $show = $usr;
		foreach my $u (keys %{$self->{UserAlias}}) {
			if ( grep($usr =~ /^$_$/,  @{$self->{UserAlias}->{$u}}) ) {
				$show = $u;
				last;
			}
		}
		my $url = &escape($usr);
		my $comma_bytes = &format_bytes($netuser_stat{$usr}{bytes});
		if ($self->{UrlReport}) {
			print $$out qq{
<tr align=right>
<td align=left><a href="../../users/$url/$url.html">$show</a></td>
};
		} else {
			print $$out qq{
<tr align=right>
<td align=left>$show</td>
};
		}
		print $$out qq{
<td>$netuser_stat{$usr}{hits}</td>
<td>$h_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
<td>$netuser_stat{$usr}{duration}</td>
<td>$d_percent</td>
};
		print $$out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
		print $$out qq{
<td>$netuser_stat{$usr}{largest_file}</td>
<td align=left>$netuser_stat{$usr}{url}</td>
</tr>};
	}
	print $$out qq{
</table>
</div>
};
	return $nuser;
}

sub _print_user_detail
{
	my ($self, $out, $outdir, $usr) = @_;

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_user_url.dat") || return;
	my %url_stat = ();
	my $total_hit = 0;
	my $total_bytes = 0;
	my $total_duration = 0;
	my $ok = 0;
	while(my $l = <$infile>) {
		chomp($l);
		my ($user, $data) = split(/\s/, $l);
		last if (($user ne $usr) && $ok);
		next if ($user ne $usr);
		$ok = 1;
		if ($data =~ /hits=(\d+);bytes=(\d+);duration=(\d+);url=(.*)/) {
			$url_stat{$4}{hits} = $1;
			$url_stat{$4}{bytes} = $2;
			$url_stat{$4}{duration} = $3;
			$total_hit += $1;
			$total_bytes += $2;
			$total_duration += $3;
		} elsif ($data =~ /hits=(\d+);bytes=(\d+);duration=(\d+);first=([^;]*);last=([^;]*);url=(.*)/) {
			$url_stat{$6}{hits} = $1;
			$url_stat{$6}{bytes} = $2;
			$url_stat{$6}{duration} = $3;
			$url_stat{$6}{firsthit} = $4 if (!$url_stat{$6}{firsthit});
			$url_stat{$6}{lasthit} = $5;
			$total_hit += $1;
			$total_bytes += $2;
			$total_duration += $3;
		}
	}
	$infile->close();
	my $nurl = scalar keys %url_stat;

	print $$out qq{
<b>$Translate{'Url_number'}:</b> $nurl<br>
};
	print $$out qq{
<div id="stata">
<table class="sortable">
<thead>
<tr align="center">
<th>$Translate{'Url'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
<th>$Translate{'Duration'}</th>
<th nowrap>% $Translate{'Time'}</th>
};
	print $$out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $$out qq{
</tr>
</thead>
};
	
	foreach my $url (sort { $url_stat{$b}{"$self->{OrderUrl}"} <=> $url_stat{$a}{"$self->{OrderUrl}"} } keys %url_stat) {
		my $h_percent = '0.0';
		$h_percent = sprintf("%2.2f", ($url_stat{$url}{hits}/$total_hit) * 100) if ($total_hit);
		my $b_percent = '0.0';
		$b_percent = sprintf("%2.2f", ($url_stat{$url}{bytes}/$total_bytes) * 100) if ($total_bytes);
		my $d_percent = '0.0';
		$d_percent = sprintf("%2.2f", ($url_stat{$url}{duration}/$total_duration) * 100) if ($total_duration);
		$url_stat{$url}{duration} = &parse_duration(int($url_stat{$url}{duration}/1000));
		my $total_cost = sprintf("%2.2f", int($url_stat{$url}{bytes}/1000000) * $self->{CostPrice});
		my $comma_bytes = &format_bytes($url_stat{$url}{bytes});
		print $$out qq{
<tr align="right">
<td align="left"><a href="http://$url/" target="_blank">$url</a></td>
<td>$url_stat{$url}{hits}</td>
<td>$h_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
<td>$url_stat{$url}{duration}</td>
<td>$d_percent</td>
};
		print $$out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
		print $$out qq{
</tr>};
	}
	print $$out qq{
</table>
</div>
};

}

sub _print_top_url_stat
{
	my ($self, $outdir, $year, $month, $day) = @_;

	my $stat_date = $self->set_date($year, $month, $day);

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_user_url.dat") || return;
	my %url_stat = ();
	my $total_hits = 0;
	my $total_bytes = 0;
	my $total_duration = 0;
	while(my $l = <$infile>) {
		chomp($l);
		my ($user, $data) = split(/\s/, $l);
		if ($data =~ /hits=(\d+);bytes=(\d+);duration=(\d+);url=(.*)/) {
			$url_stat{$4}{hits} = $1;
			$url_stat{$4}{bytes} = $2;
			$url_stat{$4}{duration} = $3;
			$total_hits += $1;
			$total_bytes += $2;
			$total_duration += $3;
		} elsif ($data =~ /hits=(\d+);bytes=(\d+);duration=(\d+);first=([^;]*);last=([^;]*);url=(.*)/) {
			$url_stat{$6}{hits} = $1;
			$url_stat{$6}{bytes} = $2;
			$url_stat{$6}{duration} = $3;
			$url_stat{$6}{firsthit} = $4 if (!$url_stat{$6}{firsthit});
			$url_stat{$6}{lasthit} = $5;
			$total_hits += $1;
			$total_bytes += $2;
			$total_duration += $3;
		}
	}
	$infile->close();

	my $nurl = scalar keys %url_stat;

	my $file = $outdir . '/url.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	my $cal = $self->_get_calendar($stat_date, $type, $outdir);
	$self->_print_header(\$out, $self->{menu}, $cal);
	for my $tpe ('Hits', 'Bytes', 'Duration') {
		my $t1 = $Translate{"Url_${tpe}_title"};
		$t1 =~ s/\%d/$self->{TopNumber}/;
		if ($tpe eq 'Hits') {
			print $out $self->_print_title($t1, $stat_date);
			print $out "<b>$Translate{'Url_number'}:</b> $nurl<br>\n";
		} else {
			print $out "<h3>$t1 $stat_date <div id=\"uplink\"><a href=\"#atop\">[ $Translate{'Up_link'} ]</a></div></h3>\n";
		}
		print $out qq{
<div id="stata">
<table class="sortable">
<thead>
<tr>
<th>$Translate{'Url'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
<th>$Translate{'Duration'}</th>
<th nowrap>% $Translate{'Time'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
<th>$Translate{'First_visit'}</th>
<th>$Translate{'Last_visit'}</th>
} if ($day);
	print $out qq{
</tr>
</thead>
};
		my $i = 0;
		foreach my $u (sort { $url_stat{$b}{"\L$tpe\E"} <=> $url_stat{$a}{"\L$tpe\E"} } keys %url_stat) {
			my $c_percent = '0.0';
			$c_percent = sprintf("%2.2f", ($url_stat{$u}{hits}/$total_hits) * 100) if ($total_hits);
			my $b_percent = '0.0';
			$b_percent = sprintf("%2.2f", ($url_stat{$u}{bytes}/$total_bytes) * 100) if ($total_bytes);
			my $d_percent = '0.0';
			$d_percent = sprintf("%2.2f", ($url_stat{$u}{duration}/$total_duration) * 100) if ($total_duration);
			my $total_cost = sprintf("%2.2f", int($url_stat{$u}{bytes}/1000000) * $self->{CostPrice});
			my $duration = &parse_duration(int($url_stat{$u}{duration}/1000));
			my $comma_bytes = &format_bytes($url_stat{$u}{bytes});
			my $firsthit = '-';
			if ($url_stat{$u}{firsthit}) {
				$firsthit = ucfirst(strftime("%b %d %T", localtime($url_stat{$u}{firsthit})));
			}
			my $lasthit = '-';
			if ($url_stat{$u}{lasthit}) {
				$lasthit = ucfirst(strftime("%b %d %T", localtime($url_stat{$u}{lasthit})));
			}
			if ($type eq 'hour') {
				if ($url_stat{$u}{firsthit}) {
					$firsthit = ucfirst(strftime("%T", localtime($url_stat{$u}{firsthit})));
				} else {
					$firsthit = '-';
				}
				if ($url_stat{$u}{lasthit}) {
					$lasthit = ucfirst(strftime("%T", localtime($url_stat{$u}{lasthit})));
				} else {
					$firsthit = '-';
				}
			}
			print $out qq{
<tr align=right>
<td align=left><a href="http://$u/" target="_blank">$u</a></td>
<td>$url_stat{$u}{hits}</td>
<td>$c_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
<td>$duration</td>
<td>$d_percent</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
	print $out qq{
<td>$firsthit</td>
<td>$lasthit</td>
} if ($day);
	print $out qq{
</tr>};
			$i++;
			last if ($i > $self->{TopNumber});
		}
		print $out qq{</table></div>};
	}

	print $out qq{
<div id="uplink">
<table align=center>
<tr>
<th><a href="#atop">[ $Translate{'Up_link'} ]</a></th>
</tr>
</table>
</div>
};
	$self->_print_footer(\$out);
	$out->close();

	return $nurl;
}

sub _print_top_domain_stat
{
	my ($self, $outdir, $year, $month, $day) = @_;

	my $stat_date = $self->set_date($year, $month, $day);

	my $type = 'hour';
	if (!$day) {
		$type = 'day';
	}
	if (!$month) {
		$type = 'month';
	}

	# Load code statistics
	my $infile = new IO::File;
	$infile->open("$outdir/stat_user_url.dat") || return;
	my %url_stat = ();
	my %domain_stat = ();
	my $total_hits = 0;
	my $total_bytes = 0;
	my $total_duration = 0;
	my %perdomain = ();
	my $url = '';
	my $hits = 0;
	my $bytes = 0;
	my $duration = 0;
	my $first = 0;
	my $last = 0;
	while(my $l = <$infile>) {
		chomp($l);
		my ($user, $data) = split(/\s/, $l);
		if ($data =~ /hits=(\d+);bytes=(\d+);duration=(\d+);url=(.*)/) {
			$url = $4;
			$hits = $1;
			$bytes = $2;
			$duration = $3;
		} elsif ($data =~ /hits=(\d+);bytes=(\d+);duration=(\d+);first=([^;]*);last=([^;]*);url=(.*)/) {
			$url = lc($6);
			$hits = $1;
			$bytes = $2;
			$duration = $3;
			$first = $4;
			$last = $5;
		}
		$url =~ /(\.[^\.]+)$/;
		if ($url !~ /\.\d+$/) {
			if ($url =~ /([^\.]+)(\.[^\.]+)$/) {
				$perdomain{$2}{hits} += $hits;
				$perdomain{$2}{bytes} += $bytes;
				$domain_stat{"$1$2"}{hits} = $hits;
				$domain_stat{"$1$2"}{bytes} = $bytes;
				$domain_stat{"$1$2"}{duration} = $duration;
				$domain_stat{"$1$2"}{firsthit} = $first if (!$domain_stat{"$1$2"}{firsthit});
				$domain_stat{"$1$2"}{lasthit} = $last;
			}
		} else {
			$perdomain{'other'}{hits} += $hits;
			$perdomain{'other'}{bytes} += $bytes;
			$domain_stat{'unknown'}{hits} = $hits;
			$domain_stat{'unknown'}{bytes} = $bytes;
			$domain_stat{'unknown'}{duration} = $duration;
			$domain_stat{'unknown'}{firsthit} = $first if (!$domain_stat{'unknown'}{firsthit});
			$domain_stat{'unknown'}{lasthit} = $last;
		}
		$total_hits += $hits;
		$total_bytes += $bytes;
		$total_duration += $duration;
	}
	$infile->close();

	my $nurl = scalar keys %domain_stat;

	my $file = $outdir . '/domain.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	my $cal = $self->_get_calendar($stat_date, $type, $outdir);
	$self->_print_header(\$out, $self->{menu}, $cal);
	for my $tpe ('Hits', 'Bytes', 'Duration') {
		my $t1 = $Translate{"Domain_${tpe}_title"};
		$t1 =~ s/\%d/$self->{TopNumber}/;
		if ($tpe eq 'Hits') {
			print $out $self->_print_title($t1, $stat_date);
			print $out "<b>$Translate{'Domain_number'}:</b> $nurl<br>\n";
			print $out qq{<table><tr><td><img src="domain_hits.png"></td><td><img src="domain_bytes.png"></td></tr></table>};
		} else {
			print $out "<h3>$t1 $stat_date <div id=\"uplink\"><a href=\"#atop\">[ $Translate{'Up_link'} ]</a></div></h3>\n";
		}
		print $out qq{
<div id="stata">
<table class="sortable">
<thead>
<tr>
<th>$Translate{'Url'}</th>
<th>$Translate{'Requests'}</th>
<th nowrap>% $Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
<th nowrap>% $Translate{'Bytes'}</th>
<th>$Translate{'Duration'}</th>
<th nowrap>% $Translate{'Time'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
<th>$Translate{'First_visit'}</th>
<th>$Translate{'Last_visit'}</th>
} if ($day);
	print $out qq{
</tr>
</thead>
};
		my $i = 0;
		foreach (sort { $domain_stat{$b}{"\L$tpe\E"} <=> $domain_stat{$a}{"\L$tpe\E"} } keys %domain_stat) {
			my $c_percent = '0.0';
			$c_percent = sprintf("%2.2f", ($domain_stat{$_}{hits}/$total_hits) * 100) if ($total_hits);
			my $b_percent = '0.0';
			$b_percent = sprintf("%2.2f", ($domain_stat{$_}{bytes}/$total_bytes) * 100) if ($total_bytes);
			my $d_percent = '0.0';
			$d_percent = sprintf("%2.2f", ($domain_stat{$_}{duration}/$total_duration) * 100) if ($total_duration);
			my $total_cost = sprintf("%2.2f", int($domain_stat{$_}{bytes}/1000000) * $self->{CostPrice});
			my $duration = &parse_duration(int($domain_stat{$_}{duration}/1000));
			my $comma_bytes = &format_bytes($domain_stat{$_}{bytes});
			my $firsthit = '-';
			if ($domain_stat{$_}{firsthit}) {
				$firsthit = ucfirst(strftime("%b %d %T", localtime($domain_stat{$_}{firsthit})));
			}
			my $lasthit = '-';
			if ($domain_stat{$_}{lasthit}) {
				$lasthit = ucfirst(strftime("%b %d %T", localtime($domain_stat{$_}{lasthit})));
			}
			if ($type eq 'hour') {
				if ($domain_stat{$_}{firsthit}) {
					$firsthit = ucfirst(strftime("%T", localtime($domain_stat{$_}{firsthit})));
				} else {
					$firsthit = '-';
				}
				if ($domain_stat{$_}{lasthit}) {
					$lasthit = ucfirst(strftime("%T", localtime($domain_stat{$_}{lasthit})));
				} else {
					$lasthit = '-';
				}
			}
			print $out qq{
<tr align=right>
<td align=left>*.$_</td>
<td>$domain_stat{$_}{hits}</td>
<td>$c_percent</td>
<td>$comma_bytes</td>
<td>$b_percent</td>
<td>$duration</td>
<td>$d_percent</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
	print $out qq{
<td>$firsthit</td>
<td>$lasthit</td>
} if ($day);
	print $out qq{
</tr>};
			$i++;
			last if ($i > $self->{TopNumber});
		}
		print $out qq{</table></div>};
	}

	print $out qq{
<div id="uplink">
<table align=center>
<tr>
<th><a href="#atop">[ $Translate{'Up_link'} ]</a></th>
</tr>
</table>
</div>
};
	$self->_print_footer(\$out);
	$out->close();

	my @labels = ();
	my @hits = ();
	my @bytes = ();
	foreach my $dom (keys %perdomain) {
		next if ($dom eq 'other');
		push(@labels, $dom);
		push(@hits, $perdomain{$dom}{hits});
		push(@bytes, int($perdomain{$dom}{bytes}/1000000));
	}
	push(@labels, 'other');
	push(@hits, $perdomain{'other'}{hits});
	push(@bytes, int($perdomain{'other'}{bytes}/1000000));
	my @legends = ();
	my @data = (
	    [@labels],
	    [@hits]
	);
	local (*IMG) = undef;
	open(IMG, ">$outdir/domain_hits.png") or die "Error: can't create file $outdir/domain_hits.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$Translate{'Domain_graph_hits_title'} $stat_date",'x_label' => $Translate{'Domains_graph'}, 'y_label' => $Translate{'Requests_graph'} || 'Requests'));
	close(IMG);

	@legends = ();
	@data = (
	    [@labels],
	    [@bytes]
	);
	local (*IMG) = undef;
	open(IMG, ">$outdir/domain_bytes.png") or die "Error: can't create file $outdir/domain_bytes.png, $!\n";
	binmode IMG;
	print IMG &gen_graph(\@legends, \@data, ('title' => "$Translate{'Domain_graph_bytes_title'} $stat_date",'x_label' => $Translate{'Domains_graph'}, 'y_label' => $Translate{'Megabytes_graph'} || $Translate{'Megabytes'}));
	close(IMG);

	return $nurl;
}

sub _gen_summary
{
	my ($self, $outdir) = @_;

	# Get all day subdirectory
        opendir(DIR, "$outdir") or die "ERROR: Can't read directory $outdir, $!\n";
        my @dirs = grep { /^\d{4}$/ && -d "$outdir/$_" } readdir(DIR);
        closedir DIR;

	my %code_stat = ();
	my %total_request =  ();
	my %total_bytes = ();
	foreach my $d (@dirs) {
		# Load code statistics
		my $infile = new IO::File;
		$infile->open("$outdir/$d/stat_code.dat") || return;
		while(my $l = <$infile>) {
			chomp($l);
			my ($code, $data) = split(/\s/, $l);
			$data =~ /hits_month=([^;]+);bytes_month=(.*)/;
			my $hits = $1 || '';
			my $bytes = $2 || '';
			$hits =~ s/,$//;
			$bytes =~ s/,$//;
			my %hits_tmp = split(/[:,]/, $hits);
			foreach my $tmp (sort {$a <=> $b} keys %hits_tmp) {
				$code_stat{$d}{$code}{request} += $hits_tmp{$tmp};
			}
			my %bytes_tmp = split(/[:,]/, $bytes);
			foreach my $tmp (sort {$a <=> $b} keys %bytes_tmp) {
				$code_stat{$d}{$code}{bytes} += $bytes_tmp{$tmp};
			}
		}
		$infile->close();
		$total_request{$d} =  $code_stat{$d}{HIT}{request} + $code_stat{$d}{MISS}{request};
		$total_bytes{$d} = $code_stat{$d}{HIT}{bytes} + $code_stat{$d}{MISS}{bytes};
	}
	my $file = $outdir . '/index.html';
	my $out = new IO::File;
	$out->open(">$file") || die "ERROR: Unable to open $file. $!\n";
	# Print the HTML header
	$self->_print_header(\$out);
	my $colspn = 2;
	$colspn = 3 if ($self->{CostPrice});
	print $out qq{
<div id="statb">
<table>
<tr>
<th>&nbsp;</th>
<th colspan="2">$Translate{'Requests'}</th>
<th colspan="2">$Translate{'Bytes'}</th>
<th colspan="$colspn">$Translate{'Total'}</th>
</tr>
<tr>
<th nowrap>$Translate{'Years'}</th>
<th>$Translate{'Hit'}</th>
<th>$Translate{'Miss'}</th>
<th>$Translate{'Hit'}</th>
<th>$Translate{'Miss'}</th>
<th>$Translate{'Requests'}</th>
<th>$Translate{'Bytes'}</th>
};
	print $out qq{
<th nowrap>$Translate{'Cost'} $self->{Currency}</th>
} if ($self->{CostPrice});
	print $out qq{
</tr>
};
	foreach my $year (sort {$b <=> $a} keys %code_stat) {
		my $comma_bytes = &format_bytes($total_bytes{$year});
		my $hit_bytes = &format_bytes($code_stat{$year}{HIT}{bytes});
		my $miss_bytes = &format_bytes($code_stat{$year}{MISS}{bytes});
		my $total_cost = sprintf("%2.2f", int($total_bytes{$year}/1000000) * $self->{CostPrice});
		print $out qq{
<tr>
<td nowrap><a href="$year/index.html">$Translate{'Stat_label'} $year</a></td>
<td>$code_stat{$year}{HIT}{request}</td>
<td>$code_stat{$year}{MISS}{request}</td>
<td>$hit_bytes</td>
<td>$miss_bytes</td>
<td>$total_request{$year}</td>
<td>$comma_bytes</td>
};
	print $out qq{
<td>$total_cost</td>
} if ($self->{CostPrice});
	print $out qq{
</tr>};
	}
	print $out qq{
</table>
</div>
<pre>
	<b>$Translate{'Hit'}:</b> $Translate{'Hit_help'}
	<b>$Translate{'Miss'}:</b> $Translate{'Miss_help'}
};
	print $out qq{
	<b>$Translate{'Cost'}:</b> $Translate{'Cost_help'} $self->{CostPrice} $self->{Currency}
} if ($self->{CostPrice});
	print $out qq{
</pre>
};
	$self->_print_footer(\$out);
	$out->close();

}

sub parse_config
{
	my ($file) = @_;

	die "FATAL: no configuration file!\n" if (!-e $file);

	my %opt = ();
	open(CONF, $file) or die "ERROR: can't open file $file, $!\n";
	while (my $l = <CONF>) {
		chomp($l);
		next if (!$l || ($l =~ /^[\s\t]*#/)); 
		my ($key, $val) = split(/[\s\t]+/, $l);
		$opt{$key} = $val;
	}
	close(CONF);

	# Check config
	if (!exists $opt{Output} || !-d $opt{Output}) {
		print STDERR "Error: you must give a valid output directory. See option: Output\n";
		exit 0;
	}
	if (!exists $opt{LogFile} || !-f $opt{LogFile}) {
		print STDERR "Error: you must give the path to the Squid log file. See option: LogFile\n";
		exit 0;
	}
	if (exists $opt{DateFormat}) {
		if ( ($opt{DateFormat} !~ m#\%y#) || ($opt{DateFormat} !~ m#\%m#) || ($opt{DateFormat} !~ m#\%d#) ) {
			print STDERR "Error: bad date format, must have \%y, \%m, \%d. See option: DateFormat\n";
			exit 0;
		}
	}
	if ($opt{Lang} && !-e $opt{Lang}) {
		print STDERR "Error: can't find translation file $opt{Lang}. See option: Lang\n";
		exit 0;
	}
	if ($opt{FooterFile} && !-e $opt{FooterFile}) {
		print STDERR "Error: can't find custom footer file $opt{FooterFile}. See option: FooterFile\n";
		exit 0;
	}
	return %opt;
}

sub parse_network_aliases
{
	my ($file) = @_;

	return if (!$file || !-f $file);

	my %alias = ();
	open(ALIAS, $file) or die "ERROR: can't open network aliases file $file, $!\n";
	my $i = 0;
	while (my $l = <ALIAS>) {
		chomp($l);
		$i++;
		next if (!$l || ($l =~ /^[\s\t]*#/));
		$l =~ s/[\s\t]*#.*//;
		my @data = split(/[\t]+/, $l, 2);
		if ($#data == 1) {
			push(@{$alias{$data[0]}}, split(/[\s,;\t]/, $data[1]));
		} else {
			die "ERROR: wrong format in network aliases file $file, line $i\n";
		}
	}
	close(ALIAS);

	return \%alias;
}

sub parse_user_aliases
{
	my ($file) = @_;

	return if (!$file || !-f $file);

	my %alias = ();
	open(ALIAS, $file) or die "ERROR: can't open user aliases file $file, $!\n";
	my $i = 0;
	while (my $l = <ALIAS>) {
		chomp($l);
		$i++;
		next if (!$l || ($l =~ /^[\s\t]*#/)); 
		my @data = split(/[\t]+/, $l, 2);
		$data[0] =~ s/\s+/_/g; # Replace space, they are not allowed
		if ($#data == 1) {
			push(@{$alias{$data[0]}}, split(/[\s,;\t]/, $data[1]));
		} else {
			die "ERROR: wrong format in user aliases file $file, line $i\n";
		}
	}
	close(ALIAS);

	return \%alias;
}

sub parse_exclusion
{
	my ($file) = @_;

	return if (!$file || !-f $file);

	my %exclusion = ();
	open(EXCLUDED, $file) or die "ERROR: can't open exclusion file $file, $!\n";
	while (my $l = <EXCLUDED>) {
		chomp($l);
		next if (!$l || ($l =~ /^[\s\t]*#/)); 
		if ($l =~ m#^USER[\s\t]+(.*)#) {
			push(@{$exclusion{users}}, split(m#[\s\t]+#, $1));
		} elsif ($l =~ m#^CLIENT[\s\t]+(.*)#) {
			push(@{$exclusion{clients}}, split(m#[\s\t]+#, $1));
		} elsif ($l =~ m#^URI[\s\t]+(.*)#) {
			push(@{$exclusion{uris}}, split(m#[\s\t]+#, $1));
		} else {
			# backward compatibility
			push(@{$exclusion{all}}, $l);
		}
	}
	close(EXCLUDED);

	return %exclusion;
}

# User URL-encode
sub escape
{
	my ($toencode) = @_;

	return undef unless defined($toencode);

	$toencode =~ s/[^a-zA-Z0-9_.-]/_/g;

	return $toencode;
}

# Set date to user format
sub set_date
{
	my ($self, $year, $month, $day) = @_;

	my $date_format = $self->{DateFormat};

        $date_format =~ s/\%y/$year/i;
        $date_format =~ s/\%m/$month/i;
        $date_format =~ s/\%d/$day/i;
        $date_format =~ s/\%M/$Translate{$month}/i;

	$date_format =~ s/([^\p{Letter}\p{Digit}]){2,3}/$1/;
	$date_format =~ s/^[^\p{Letter}\p{Digit}]+//;
	$date_format =~ s/[^\p{Letter}\p{Digit}]+$//;

        return $date_format;
}

# Format bytes with comma for better reading
sub format_bytes
{
	my $text = reverse $_[0];

	$text =~ s/(\d\d\d)(?=\d)(?!\d*\.)/$1,/g;

	return scalar reverse $text;
}

sub gen_graph
{
	my ($legends,$values,%param) = @_;

	my $graph = '';
	if (!$param{'type'} || ($param{'type'} eq 'area')) {
		$graph = new GD::Graph::bars3d($param{'width'} || 500, $param{'height'} || 250);
		$graph->set(
			x_label         => $param{'x_label'} || '',
			y_label         => $param{'y_label'} || '',
			title           => $param{'title'} || '',
			fgclr           => '#993300',
			legendclr       => '#993300',
			dclrs           => [ qw(lorange lgray lbrown lyellow lgreen lblue lpurple lred) ],
			x_labels_vertical => $param{'vertical'},
			long_ticks  => 1,
			shadow_depth => 5,
			box_axis => 0,
			show_values     => $param{'show_values'},
		) or die $graph->error;
	} elsif ($param{'type'} eq 'pie') {
		$graph = new GD::Graph::pie3d($param{'width'} || 500, $param{'height'} || 250);
		$graph->set(
			title   => $param{'title'} || '',
			fgclr   => '#993300',
			dclrs   => [ qw(lorange lgray lbrown lyellow lgreen lblue lpurple lred) ],

		) or die $graph->error;

	}

	$graph->set_text_clr('#993300');
	$graph->set_legend(@$legends) if ($#{$legends} >= 0);

	my $gd = $graph->plot($values) or die $graph->error;
	return $gd->png;
}

sub _print_title
{
	my ($self, $title, $stat_date) = @_;

	my $para = "<table><tr><td>\n";
	$para .= "<h3>$title $stat_date</h3>\n";
	$para .= "</td></tr></table>\n";

	return $para;
}

sub _get_calendar
{
	my ($self, $stat_date, $type, $outdir, $prefix) = @_;

	my $para = "<div id=\"calendar\">\n";
	if ($type eq 'day') {
		$para .= "<table><tr><th colspan=\"8\">$stat_date</th></tr>\n";
		for my $i ('01' .. '32') {
			$para .= "<tr>" if (grep(/^$i$/, '01', '09', '17','25'));
			if ($i == 32) {
				$para .= "<td>&nbsp;</td>";
			} elsif (-f "$outdir/$i/index.html") {
				$para .= "<td><a href=\"$prefix$i/index.html\">$i</a></td>";
			} else {
				$para .= "<td>$i</td>";
			}
			$para .= "</tr>\n" if (grep(/^$i$/, '08', '16', '24', '32'));
		}
		$para .= "</table>\n";
	} elsif ($type eq 'month') {
		$para .= "<table><tr><th colspan=\"4\">$stat_date</th></tr>\n";
		for my $i ('01' .. '12') {
			$para .= "<tr>" if (grep(/^$i$/, '01', '05', '09'));
			if (-f "$outdir/$i/index.html") {
				$para .= "<td><a href=\"$prefix$i/index.html\">$Translate{$i}</a></td>";
			} else {
				$para .= "<td>$Translate{$i}</td>";
			}
			$para .= "</tr>\n" if (grep(/^$i$/, '04', '08', '12'));
		}
		$para .= "</table>\n";
	}
	$para .= "</div>\n";

	return $para;
}

sub anonymize_id
{
        my $u_id = '';
        while (length($u_id) < 16) {
                my $c = chr(int(rand(127)));
                if ($c =~ /[a-zA-Z0-9]/) {
                        $u_id .= $c;
                }
        }

        return 'Anon' . $u_id;

}

1;

__END__

