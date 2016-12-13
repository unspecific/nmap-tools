#!/usr/bin/perl
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
#   * Neither the name of MadHat Productions nor the names of its
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

use POSIX "strftime";
use Getopt::Std;
getopts("vd:s:i:b:");

# -s for subnet
# -i for IP, faster if used with -s
# -d debug
# -v verbose (tells removed ports as well)
# -b for the number of days back to go for the base
#    this will still compair to the latest scan

# where the nmap logs are stored
$logdir = "/home/ysec/logs";

##############################################################
#
#
$sdate = time - 86400;
if ($opt_b > 2) {
  $bdate = time - $opt_b * 86400;
} else {
  $bdate = time - 172800;
}
$basedate = strftime "%m%d%Y", localtime $bdate;
$scandate = strftime "%m%d%Y", localtime $sdate;
print "Compairing $basedate to $scandate\n" if ($opt_d);

opendir(DIR, $logdir);
@dir = readdir(DIR);
close(DIR);

FILE: for $file (@dir) {
  next FILE if ($file =~ /^\./);
  next FILE if ($opt_s and $file !~ /$opt_s/);
  if ($file =~ /^$basedate(\.\d{1,3}\.\d{1,3}\.\d{1,3}\.nmap)$/) {
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
              $data .= sprintf("  +%5u/tcp   open   %s\n", $port, $name)
                unless (($port == 80 or $port == 443 ) and !$opt_v);
            } elsif (
                $base_port{$port} eq 'closed' 
                and $state eq 'open'
              ) {
              print "Closed -> Open $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  +%5u/tcp   open   %s\n", $port, $name)
                unless (($port == 80 or $port == 443 ) and !$opt_v);
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
                unless ( ($port == 80 or $port == 443) and !$opt_v);
            } elsif (
                !$base_port{$port}
                and $state eq 'open'
              ) {
              print "Opened from N/A $ip:$port\n" if ($opt_d > 1);
              $data .= sprintf("  +%5u/tcp   open   %s\n", $port, $name)
                unless ( ($port == 80 or $port == 443) and !$opt_v);
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
        if (
          $data =~ /\s[\-\+]\s/ and 
          ( 
            $data !~ m<^\s{2}\+\s{3}25/tcp\s{3}open\s{3}smtp\n$>sx 
            and $dns !~ /\.mail\./
          )
        ) {
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
