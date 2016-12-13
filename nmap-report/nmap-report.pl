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
getopts("svVp:d:b:f");

$logdir = "/home/lheath/mp/nmap-logs";

if ($opt_b) {
  $sdate = time - 86400 * $opt_b;
} else {
  $sdate = time;
}
$scandate = strftime "%m%d%Y", localtime $sdate;
print "Searching $scandate\n" if ($opt_d);

opendir(DIR, $logdir);
@dir = readdir(DIR);
close(DIR);

FILE: for $file (@dir) {
  next FILE if ($file =~ /^\./);
  if ($file =~ /^$scandate(\.\d{1,3}\.\d{1,3}\.\d{1,3}\.nmap)$/) {
    $exten = $1;
    print "searching $scandate$exten for open port $opt_p\n" if ($opt_d);
    open (SCAN, "$logdir/$scandate$exten");
    @scan = <SCAN>;
    close (SCAN);
    @scan = grep(!/^#/, @scan);
    LINE: for $line (@scan) {
      chomp $line;
      ($host, $ports, @ignored) = split ("\t", $line);
      ($title, $ip, $dns) = split(' ', $host);
      for (@ignored) {
        ($title, $info) = split(':', $_);
        if ($title eq 'OS') {
          $host{$ip}{'os'} = $info;
        } elsif ($title eq 'Ignored State') {
          $host{$ip}{'ignore'} = $info;
        } elsif ($title eq 'Seq Index') {
          $host{$ip}{'index'} = $info;
        } elsif ($title eq 'IPID Seq') {
          $host{$ip}{'seq'} = $info;
        }
      }
      ($title, $port_info) = split(':', $ports);
      next LINE if ($title ne "Ports");
      if ($opt_p and $port_info !~ / $opt_p\/open/) {
        next;
      }
      if ($opt_v) {
        print "$ip $dns\n";
      } elsif ($opt_f and $opt_p) {
        print "$ip:$opt_p\n";
      } elsif(!$opt_f) {
        print "$ip\n";
      }
      if ($opt_d) {
        print "Name: $dns\n";
        print "\tPort Info: $port_info\n";
        print "-" x 70 . "\n";
      } 
      if (!$opt_p and $opt_v and !$opt_f) {
        $port_info =~ s/\//\t/ig;
        $port_info =~ s/\,/\n\t/ig;
        print "\t$port_info\n";
      } elsif ($opt_f and !$opt_p) {
        for $ports (split ',', $port_info) {
          if ($ports =~ /open/) {
            $ports =~ s/\s//g;
            @port_data = (split'/', $ports);
            print "$ip:$port_data[0]\n";
          }
        }
      }
      if ($opt_V and !$opt_f) {
        print "\t OS:            $host{$ip}{'os'}\n";
        print "\t Ignored:       $host{$ip}{'ignore'}\n";
        print "\t Seq Index:     $host{$ip}{'seq'}\n";
        print "\t IPID Sequence: $host{$ip}{'index'}\n\n";
      }
    }
  } else {
    next FILE;
  }
}
