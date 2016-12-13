#!/usr/bin/perl
#
#----------------------------------------------------------------------------
#
#  Written by MadHat (madhat@unspecific.com)
#    http://www.unspecific.com/nmap/report/
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
#----------------------------------------------------------------------------

# log directory where nmap-wrapper stored its log files
my $logdir = "/usr/local/var/log/nmap";

#---------------------------------------
# Don't change anything below here
#---------------------------------------
$VERSION = '1.1';

use Chart::Lines;

print " : nmap-graph - $VERSION - MadHat (at) Unspecific.com\n";
print " : http://www.unspecific.com/nmap/graph/\n\n";

my %history;
my @labels;
my @hosts;
my @ports;

opendir (DIR, $logdir);
my @files = readdir(DIR);
closedir(DIR);

for my $file (sort @files) {
  next if ($file =~ /^\./);
  if ($file =~ /^(\d{8})\.\d{1,3}\.\d{1,3}\.\d{1,3}\.gnmap$/) {
    my $date = $1;
    open (FH, "$logdir/$file") or warn("ERROR opeing $logdir/$file: $!");
    while (<FH>) {
      my $line = $_;
      next if ($line =~ /^#/);
      chomp;
      my @line = split("\t");
      for my $fields (@line) {
        my ($field, $data) = split (":", $fields);
        if ($field =~ /^Host$/) {
          $history{$date}{'hosts'}++;
        } # end if Host
        if ($field =~ /^Ports$/) {
          my @ports = split(",", $data);
          for my $port (@ports) {
            if ($port =~ /^\s*\d+\/open\//) {
              $history{$date}{'ports'}++;
            }
          }
        } # end if Host
      } # end for $fields
    } # end while FH
  } # end if file
} # end files

for my $date (sort keys %history) {
  print $date . ":" . $history{$date}{'hosts'} . ":" . $history{$date}{'ports'} . "\n";
  $date =~ /^\d{4}(\d{2})(\d{2})$/;
  push @labels, "$1-$2";
  push @hosts, $history{$date}{'hosts'};
  push @ports, $history{$date}{'ports'};
}
splice(@labels, 0, -14); 
splice(@hosts, 0, -14); 
splice(@ports, 0, -14); 


my $host_obj = Chart::Lines->new ( 600, 200 );
$host_obj->set(
    title           => 'Hosts/Day',
    legend          => 'none',
    y_label         => 'Hosts',
    grey_background => 0,
    x_label         => 'Date',
    precision       => 0,
    colors          => {
         y_label    => [0x00, 0x00, 0x00],
         x_label    => [0x00, 0x00, 0x00],
         text       => [0x00,0x00,0x00],
         dataset0   => [0xff,0,0],
         background => [0xFF, 0xFF, 0xFF],
    },
  );

my @host_data = (\@labels, \@hosts);
$host_obj->png ("/var/www/hosts.png", \@host_data);

my $port_obj = Chart::Lines->new ( 600, 200 );
$port_obj->set(
    title           => 'Ports/Day',
    legend          => 'none',
    grey_background => 0,
    y_label         => 'Ports',
    x_label         => 'Date',
    precision       => 0,
    colors          => {
         y_label    => [0x00, 0x00, 0x00],
         x_label    => [0x00, 0x00, 0x00],
         text       => [0x00,0x00,0x00],
         dataset0   => [0xff,0,0],
         background => [0xFF, 0xFF, 0xFF],
    },
  );

my @port_data = (\@labels, \@ports);
$port_obj->png ("/var/www/ports.png", \@port_data);
