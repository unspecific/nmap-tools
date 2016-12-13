#!/usr/bin/perl
# 
# nmap-search.pl
# Written by MadHat (madhat@unspecific.com)
# http://www.unspecific.com/nmap/search/
#
# Basically, this will allow you to search through a nmap -oG (grepable) 
# file to look for specific things and reformat it for you. 
#
# Copyright (c) 2001-2003, MadHat (madhat@unspecific.com)
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

# log directory where nmap-wrapper stored its log files
$logdir = "/usr/local/var/log/nmap";

#---------------------------------------
# Don't change anything below here
#---------------------------------------
$VERSION = '1.2';

if (defined $ENV{'REQUEST_METHOD'}) {
  use CGI ":standard";
  use CGI::Carp "fatalsToBrowser";
  print header, start_html('NMAP Search'), "<pre>";
  opendir (DIR, $logdir) or die "ERROR: Unable able to open $logdir: $!\n";
  @data = readdir(DIR);
  closedir(DIR);
  for (@data) {
    if (/\.gnmap$/) {
      ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,
       $atime,$mtime,$ctime,$blksize,$blocks)
           = stat("$logdir/$_") or  die "ERROR: Unable able to open $_: $!\n";;
      $mtime = localtime($mtime);
      $dblabel{$_} = "$_ - $mtime";
      push(@dblist, $_);
    }
  }

  if (param('nmapdb')) {
    if (param('nmapdb') =~ /^\// or param('nmapdb') =~ /\.\./g) {
      error("problem with DB entry (" . param('nmapdb'). ") lets not try that again");
    }
    $dbfile = param('nmapdb');
  } else {
    $dbfile = "db.nmap";
  }

  if (!param('field') and !param('search')) {
    print &search_page;
    exit;
  } elsif (!param('field') or !param('search')) {
    error("lack of input data");
  }


  $srch_field = param('field');
  $srch_search = param('search');
  $html = 1;
} else {
  use Getopt::Std;
  getopts('f:');

  if (!$ARGV[1]) {
    print " : nmap-search v$VERSION - MadHat (at) Unspecific.com\n"
      . " : http://www.unspecific.com/nmap/search/\n\n"
      . "usage: $0 [-f file] <field> <search>\n\n"
      . "<field> The field you want to look for (OS, host, port)\n"
      . "\tmay be shortened to the shortist non-duplicated string\n"
      . "\tos may be o, host may be h, etc...\n\n"
      . "<search> is the search string you want to look for\n"
      . "\tto search for an open port use port/state (21/open)\n\n"
      . "\tyou can use the bang (!) at the begining of a search\n"
      . "\tto look for entries that do not contain that string \n"
      . "\tto look for non Microsoft product, \n"
      . "\tlook for 'os' and '!microsoft'\n\n"
      . "\tentries seperated by a space are automatically ORed\n"
      . "\tbut, the first one will determin the NOT(!) or not...\n"
      . "\tso, if I used 'OS' for my field and\n"
      . "\t'!microsoft windows cisco'\n"
      . "\tthis would find all entries that did not have \n"
      . "\tmicrosoft, windows or cisco in the OS field.\n"
      . "[-f file] for the nmap (-oG) file you want to use as the DB\n\n";
    exit;
  } else {
    $html = '';
    if ($opt_f) {
      $dbfile = $opt_f;
    } else {
      $dbfile = "db.nmap";
    }
    $srch_field = $ARGV[0];
    $srch_search = $ARGV[1];
  }
}

open (DB, "$logdir/$dbfile") or error("Can't open DB($dbfile): $!\n");
@data = <DB>;
close (DB);


if ($srch_search =~ /^!(.+)$/) { 
  print "NOT ";
  $srch_search = $1;
  $srch_search_not = 1;
}
print "searching for $srch_search ";
if ($srch_field =~ /^!(.+)$/) { 
  print "NOT ";
  $srch_field = $1;
  $srch_field_not = 1;
}
print "in field $srch_field\n";
$srch_search =~ s/\s+/\|/g;

for (@data) {
  my %entry = ();
  next if (/^#/ or /^$/);
  chomp;
  s/\cM//;
  my @line = split("\t");
  for my $entry (@line) {
    $entry =~ /^(\S+)\: (.+)$/;
    $field = $1;
    $data = $2;
    $entry{$field} = $data;
    if ($srch_search_not and !$srch_field_not) {
      if ($field =~ /^$srch_field/ig and $data !~ /$srch_search/ig) {
        $flag = 1;
      }
    } elsif ($srch_search_not and $srch_field_not) {
      if ($field !~ /^$srch_field/ig and $data !~ /$srch_search/ig) {
      	$flag = 1;
      }
    } elsif (!$srch_search_not and $srch_field_not) {
      if ($field !~ /^$srch_field/ig and $data =~ /$srch_search/ig) {
        $flag = 1;
      }
    } else {
      if ($field =~ /^$srch_field/ig and $data =~ /$srch_search/ig) {
        $flag = 1;
      }
    }
  }
  if ($flag) {
    $count++;
    $output .= "-" x 40 . "\n";
    $flag = 0;
    for $field (sort keys %entry) {
      $output .= "$field: $entry{$field}\n" unless ($field eq "Ports");
      if ($field eq "Ports") {
        $entry{$field} =~ s/\//\t/ig;
        $entry{$field} =~ s/\,/\n\t/ig;
        $output .= "$field:\n";
        $output .= "\t$entry{$field}\n";
      }
    }
    $output .= "\n\n";
  }
}
$count = $count?$count:0;
print "$count entries found\n\n";
print "$output";

sub error {
  ($error) = @_;
  print start_html("Error") if ($html);
  print "Error: $error";
  exit;
}

sub search_page {
  $data = "<form method=post> <center><table>
<tr><td align=right>Field:</td><td><input name=field></td></tr>
<tr><td align=right>Search:</td><td><input name=search></td></tr>
<tr><td align=right>DB to Search:</td><td>";
  $data .= popup_menu(-name=>nmapdb, -values=>\@dblist, -labels=>\%dblabel);
  $data .= "<tr><td colspan=2 align=center><input type=submit></td></tr></table></center>
<pre>
<b>field</b> The field you want to look for (OS, host, port)
	may be shortened to the shortist non-duplicated string
	os may be o, host may be h, etc...

<b>search</b> is the search string you want to look for
	to search for an open port use port/state (21/open)

	you can use the bang (!) at the begining of a search
	to look for entries that do not contain that string 
	to look for non Microsoft product, 
	look for 'os' and '!microsoft'

	entries seperated by a space are automatically ORed
	but, the first one will determin the NOT(!) or not...
	so, if I used 'OS' for my field and
	'!microsoft windows cisco'
	this would find all entries that did not have 
	microsoft, windows or cisco in the OS field.

<b>DB></b> for the nmap (-oG) file you want to use as the DB
	The files listed are the local DBs
	The date/time stamp is the date they should have been created.

</pre>";

  return($data);
}
