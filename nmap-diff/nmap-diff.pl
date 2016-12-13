#!/usr/bin/perl
#---------------------------------------
#
#   Writen by MadHat (madhat@unspecific.com)
# http://www.unspecific.com/nmap/diff/
#
# Copyright (c) 2001-2002, MadHat (madhat@unspecific.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the distribution.
#   * Neither the name of Unspecific Consulting nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#---------------------------------------

# where the nmap logs are stored
my $logdir = "/usr/local/var/log/nmap";
# sendmail
my $sendmail = "/usr/sbin/sendmail";

#---------------------------------------
# Don't change anything below here
#---------------------------------------
$VERSION = '1.3';
##############################################################
#
#
use POSIX "strftime";
use Getopt::Std;
getopts("hvd:s:i:b:l:m:");
#
if ($opt_h) {
  &usage;
}
if ($opt_l) {
  $logdir = $opt_l;
}
#
#my $html = 0;
#
#
if (defined $ENV{'REQUEST_METHOD'}) {
  $html = 1;
  use CGI ":standard";
  use CGI::Carp "fatalsToBrowser";
  print header, start_html('NMAP Diff');
  if (param('d') =~ /^(\d)$/) {
    $opt_d = $1;
  } 
  $opt_v = 1;
  print "<form method=get>\n";

  if (param('bdate') =~ /^\d{8}$/ and param('bdate') > 20081202) {
    $basedate = param('bdate');
  } else {
    $bdate = time - 86400; # - 172800;
    $basedate = strftime "%Y%m%d", localtime $bdate;
  }
  print "<input name='bdate' value='$basedate' size='8'> Base Date (Initial Scan YYYYMMDD)<br>\n";
  if (param('sdate') =~ /^\d{8}$/ and param('sdate') > 20081202) {
    $scandate = param('sdate');
  } else {
    $sdate = time;
    $scandate = strftime "%Y%m%d", localtime $sdate;
  }
  print "<input name='sdate' value='$scandate' size='8'> Scan Date (Compair Scan YYYYMMDD)<br>\n";
  if ($sdate < $bdate) {
    die("Base Date can NOT be BEFORE the Scan Date");
  }
  if (
      param('ip') =~ /^(\d{1,3}\.\d{1,3})$/ or
      param('ip') =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3})$/
    ) {
    $ip = $1;
    $opt_s = $ip;
  } elsif (
      param('ip') =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/
    ) {
    $ip = $1;
    $opt_i = $ip;
  }
  print "<input name=ip value='$ip' size=14> Search IP (Partial IP Works XXX.XXX)<br>\n";
  print "<input type=submit value='Show Diff'>\n";

  print "<pre>\n";
} else {
  $sdate = time; # - 86400;
  if ($opt_b > 2) {
    $bdate = time - $opt_b * 86400;
  } else {
    $bdate = time - 86400; # - 172800;
  }
  $basedate = strftime "%Y%m%d", localtime $bdate;
  $scandate = strftime "%Y%m%d", localtime $sdate;
}
if ($opt_i =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/) {
  $opt_s = $1;
}
print "Compairing $basedate to $scandate\n" if ($opt_v or $opt_d);

opendir(DIR, $logdir) or die "ERROR: Unable to open $logdir: $!\n";
@dir = readdir(DIR);
close(DIR);

if ($opt_m) {
  open(STDOUT,"| $sendmail -t") or die "Unable to open sendmail";
  print "To: $opt_m\n";
  print "Subject: Port Changes from $basedate to $scandate\n\n";
}
FILE: for $file (@dir) {
  next FILE if ($file =~ /^\./);
  next FILE if ($opt_s and $file !~ /$opt_s/);
  print "examining $file\n" if ($opt_d > 3);
  if ($file =~ /^$basedate(\.\d{1,3}\.\d{1,3}\.\d{1,3}\.gnmap)$/) {
    $exten = $1;
    print "compairing $basedate$exten to $scandate$exten\n" if ($opt_d);
    open (BASE, "$logdir/$basedate$exten");
    @base = <BASE>;
    close (BASE);
    open (SCAN, "$logdir/$scandate$exten");
    @scan = <SCAN>;
    close (SCAN);
    @base = grep(!/^#/, @base);
    @scan = grep(!/^#/, @scan);
    LINE: for $cur_scan (@scan) {
      my $data;
      chomp $cur_scan;
      ($host, $ports, $ignored) = split ("\t", $cur_scan);
      ($title, $ip, $dns) = split(' ', $host);
      next LINE if ($opt_i and $ip ne $opt_i);
      ($title, $port_info) = split(':', $ports);
      next LINE if ($title ne "Ports");
      print "$cur_scan\n" if ($opt_d > 3);
      for $base_scan ( grep(/\s$ip\s/, @base) ) {
        chomp $base_scan;
        print "$ip found in both files\n" if ($opt_d);
        next LINE if ($cur_scan eq $base_scan);
        print "Base Scan and New Scan do not Match\n" if ($opt_d);
        print "$cur_scan\n$base_scan\n" if ($opt_d > 3);
        ($bhost, $bports, $bignored) = split ("\t", $base_scan);
        if ($ignored ne $bignored and ($opt_v and $opt_d)) {
          print "IGNORED entry changed: $bignored -> $ignored\n";
        }
        next if ($bports eq $ports);
        ($btitle, $bip, $bdns) = split(' ', $host);
        ($btitle, $bport_info) = split(':', $bports);
        next if ($btitle ne "Ports");
        @bports = split(',', $bport_info);
        if ($dns ne $bdns and ($opt_v or $opt_d)) {
          print "DNS entry changed: $bdns -> $dns\n";
        }
        for $port_det (@bports) {
          $port_det =~ s/\s//g;
          ($port, $state, $proto, $info, $name) = split('/',$port_det);
          $base_port{$port} = $state;
        }
        @ports = split(',', $port_info);
        if ($#ports ne $#bports and $opt_d) {
          print "Number of ports changed: $#bports -> $#ports\n";
        }
        for $port_det (@ports) {
          $port_det =~ s/\s//g;
          ($port, $state, $proto, $info, $name) = split('/',$port_det);
          print "Compairing $ip:$port - $base_port{$port} => $state\n" if ($opt_d > 1);
          if ($state) {
            if (
                $base_port{$port} eq 'filtered' 
                and $state eq 'open' 
              ) {
              print "Filtered -> Open $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  +%5u/tcp   open   %s\n", $port, $name);
            } elsif (
                $base_port{$port} eq 'closed' 
                and $state eq 'open'
              ) {
              print "Closed -> Open $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  +%5u/tcp   open   %s\n", $port, $name);
            } elsif (
                $base_port{$port} eq 'open' 
                and $state eq 'filtered'
                and $opt_v
              ) {
              print "Opened -> Filtered $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  -%5u/tcp   open   %s\n", $port, $name);
            } elsif (
                $base_port{$port} eq 'open' 
                and !$state
              ) {
              print "GONE $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  -%5u/tcp   open   %s\n", $port, $name)
                unless (!$opt_v);
            } elsif (
                !$base_port{$port}
                and $state eq 'open'
              ) {
              print "Opened from N/A $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  +%5u/tcp   open   %s\n", $port, $name)
                unless (!$opt_v);
            } elsif (
                $base_port{$port} eq 'open' 
                and $state eq 'closed'
                and $opt_v
              ) {
              print "Opened -> Closed $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  -%5u/tcp   open   %s\n", $port, $name);
            } elsif (
                $base_port{$port} eq 'closed' 
                and $state eq 'filtered'
                and $opt_d
                and opt_v
              ) {
              print "Closed -> Filtered $ip:$port\n" if ($opt_d > 1);
            } elsif (
                $base_port{$port} eq 'filtered' 
                and $state eq 'closed'
                and $opt_d
                and $opt_v
              ) {
              print "Filtered -> Closed $ip:$bport\n" if ($opt_d > 1);
            } elsif (
                $base_port{$port} eq 'open' 
                and $state eq 'open'
              ) {
              print "No change here, echoing state $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("   %5u/tcp   open   %s\n", $port, $name);
            }
          }
        }
	if ( $data =~ /\s[\-\+]\s/ ) {
	  print "$ip $dns\n";
	  print "$data\n";
	  print "-" x 70 . "\n$port_info\n$bport_info\n" if ($opt_d > 2);
	}
        print "-" x 70 . "\n" if ($opt_d);
      }
    }
  } else {
    next FILE;
  }
}
if ($opt_m) {
  close (STDOUT);
}
1;


sub usage {
  print " : nmap-diff - v$VERSION - MadHat (at) Unspecific.com\n";
  print " : http://www.unspecific.com/nmap/diff/\n\n";

  print <<_EOF_;
    nmap-diff is designed to be used with the log files
      generated from the nmap-wrapper

$0 [-hv] [-s <subnet>] [-i <ip>] [-b <days>]  \
          [-m <email>] [-l <logdir>]

  -h help (this stuff)
  -v is for verbose.  This will add all changed ports.  
     Default is to only who new open ports
  -s <subnet> shows only thaing in that subnet.  
     At this time the subnet accepted is a class C only.
  -i <IP> only reports on that specific IP.
  -b <days> sets the base to <days> days back and compares 
     to yesterday's scan.  so -b 7 will compare the current 
     scan to the scan from 1 week ago
  -l <logdir> to specify where the log directory
     This can be hard coded by editing the script
  -m <email> to email the output to <email> when the report 
     is generated

_EOF_
  exit 1;
}
