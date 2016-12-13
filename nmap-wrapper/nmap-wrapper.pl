#!/usr/bin/perl
#---------------------------------------
#
#   Writen by MadHat (madhat@unspecific.com)
# http://www.unspecific.com/
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

# location of nmap
my $nmap = '/usr/local/bin/nmap';

# location of log file
my $logdir = '/usr/local/var/log/nmap';

# location of blacklist file
my $blacklist = '/usr/local/etc/nmap/blacklist';

#---------------------------------------
# Don't change anything below here
#---------------------------------------
my $VERSION = '1.5';

use Getopt::Std;
use Time::HiRes qw(alarm);
use POSIX ":sys_wait_h";
use POSIX "strftime";
use Socket qw(:DEFAULT :crlf);
require v5.6.0;

$SIG{CHLD}='IGNORE';
$| = 0;
my $start_time = time;

my @scan_type = ('-O', '-sT', '-F');
my $output_type = '--append-output -oA';
my $scandate = strftime "%Y%m%d", localtime;


#---------------------------------------
# MAIN STUFF
#---------------------------------------

getopts("hvd:l:L:n:i:p:o:b:");
&scan_usage if ( defined($opt_h) );
&scan_usage if ( !( defined($opt_i) xor defined($opt_l) ) );
$opt_n = 10  if ( ! defined($opt_n) );
$opt_p = "/usr/local/var/run/wrapper.pid" if ( ! defined($opt_p) );
$logdir = $opt_L if ( defined($opt_L) );
$blacklist = $opt_b if ( defined($opt_b) );

if ($opt_o) {
  @scan_type = ();
  for my $opt (split(/\s\-/, $opt_o)) {
    if ($opt =~ /^\-/) {
      push @scan_type, $opt;
    } else {
      push @scan_type, "-$opt";
    }
  }
}

if (! -d $logdir) {
  die "ERROR: Can't find LOGDIR: $opt_L:$!\n";
}

my @blacklist;

if (-e $blacklist) {
  open(BL, $blacklist) or die "ERROR: can't open blacklist file ($blacklist): $!\n";
  @blacklist = <BL>;
  close(BL);
}

open (PID, ">$opt_p") or die "ERROR: can't open PID file ($opt_p): $!\n";
print PID "PARRENT $$ ***\n";
close(PID);

&doScan;
while (wait != -1)  { sleep 1 };
print "\n--\nScan Finished.\n" if ($opt_v);
$end_time = time;
$timediff = $end_time - $start_time;
$ipcount = $#totallist + 1;
open (PID, ">$opt_p") or die "ERROR: can't open PID file ($opt_p): $!\n";
close(PID);
print "Scan of $ipcount ip(s) took $timediff seconds\n" if ($opt_v);

sub doScan{
  print "Debug Level: " . $opt_d . "\n" if ($opt_d);
  my @nets;
  if ( defined($opt_i) ){
    open(FIN, "$opt_i" ) || die "cannot open $opt_i\n";
    @nets=<FIN>;
    close(FIN);
  } elsif ( defined($opt_l) ) {
    @nets = split(',', $opt_l);
  }
  foreach $net (@nets){
    chomp $net;
    next if ($net =~ /^#/ or $net =~ /^$/);
    print "scanning $net\n" if (defined($opt_v));
    @iplist = calculate_ip_range($net);
    push(@totallist, @iplist);
  }
  scanNet(@totallist);
}


sub end_proc {
  open (PID, ">$opt_p") or die "ERROR: can't open PID file ($opt_p): $!\n";
  close(PID);
  kill 9, $$;
}

sub scanNet{
  my @iplist = @_;
  if (!@iplist) { die "Error in the IP list. Check syntax.
    IP list entered: $ip
    Allowed Syntax:
    a.b.c.d/n       - 10.0.0.1/25
    a.b.c.*         - 10.0.0.* (0-255) same as /24
    a.b.c.d/w.x.y.z - 10.0.0.0/255.255.224.0 (standard format)
    a.b.c.d/w.x.y.z - 10.0.0.0/0.0.16.255    (cisco format)
    a.b.c.d-z       - 10.1.2.0-12
    a.b.c-x.*       - 10.0.0-3.*  (last octet has to be * or 0)
    a.b.c-x.d       - 10.0.0-3.0
    hostname        - www.unspecific.com
  \n"; }
  my $prnt=1;  # 
  my @CHILDREN;
  my %CHILDREN;
  for ( $i = 0; $i<=$#iplist; $i++ ){
    my $ipaddr = $iplist[$i];
    chomp $ipaddr;
    if (grep(/^$ipaddr$/, @blacklist)) {
      print "- DEBUG ($$): Skipping $ipaddr - BLACKLISTED\n" 
        if ($opt_d);
      next;
    }
    WAIT: while ( $#CHILDREN >= $opt_n ){
      print "- DEBUG ($$): Parent waiting to start #$i of " .
        ($#iplist + 1) . " ($#CHILDREN Running)\n" 
        if ($opt_d);
      open (PID, ">$opt_p") or die "ERROR: can't open PID file ($opt_p): $!\n";
      print PID "WRAPPER $$\n";
      for my $chpid (keys %CHILDREN) {
        print PID "CHILD $chpid " . $CHILDREN{$chpid} . "\n";
      }
      close (PID);
      my $CHILD_pos = 0;
      for my $pid (@CHILDREN) {
        $waitpid = waitpid($pid, WNOHANG);
        if ($waitpid != 0) {
          splice(@CHILDREN, $CHILD_pos, 1);
	  delete $CHILDREN{$pid};
          kill 9, $pid;
          next WAIT;
        }
        $CHILD_pos++;
      } 
      sleep 1;
    }
    my $thisthread = fork unless ($#iplist == 0);
    if ( !defined($thisthread) and $#iplist >= 1 ) {
      print "FORK Died $ipaddr <=========\n"; 
    } else {
      if ( $thisthread == 0 ) {
        #################################################
        $0 = "nmap-scanning $ipaddr";
        $ipaddr =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/;
        $subnet = $1;
        print "Scanning $ipaddr, output to $logdir/$subnet\n" 
          if ($opt_d);
        push(@scan_type, "$output_type $logdir/$scandate.$subnet", $ipaddr, '2>/dev/null');
	print STDERR "Starting $nmap @scan_type\n" if $opt_d > 3;
        
        $rc = `$nmap @scan_type`;
        #################################################
        exit 0 unless ($#iplist == 0);
      } else {
        # parent
        $SIG{INT}=\&end_proc;
        $prnt=1;
        print "- DEBUG ($$): This is the Parent for pid $thisthread scanning $ipaddr\n" 
          if ($opt_d > 1);
        push ( @CHILDREN, $thisthread);
	$CHILDREN{$thisthread} = $ipaddr;
      }
    }
  }
}

sub scan_usage{
  print "\n : nmap-wrapper v$VERSION - MadHat (at) Unspecific.com\n";
  print " : http://www.unspecific.com/nmap/wrapper/\n\n";
  print "$0 < -hav > -i <filename> |  -l <host_list> \\
         [ -n <num_children>] [-p <pid_file> ] [ -o \"<nmap options>\" ] \\
	 [ -L <log_dir> ] [-b blacklist]
         options:\n";
  print "  -h   help (this stuff)\n";
  print "  -v   verbose - will add details\n";
  print "  -l   network list in comma delimited form: a.b.c.d/M,e.f.g.h/x.y.z.M\n";
  print "  -i   input file containing network list, one network per line\n";
  print "  -n   max number of children to fork\n";
  print "  -o   nmap options to send to each child process\n";
  print "         it is expecting the \"\" around the options\n";
  print "         Default Options:  -O -sT -F\n";
  print "  -p   PID file, lists the currently running processes and their state\n";
  print "        default location is /usr/local/var/run/wrapper.pid\n";
  print "  -L   Log file dir.  This is where scan results are stored\n";
  print "        default location is /usr/local/var/log/wrapper/\n";
  print "  -b   blacklist.  file that contains a list of IPs to NOT scan\n";
  print "        default location is /usr/local/etc/nmap/blacklist\n";
  exit 0;
}


sub calculate_ip_range {
  # 1st IP scalar
  #  formats allowed include
  #    a.b.c.d/n       - 10.0.0.1/25
  #    a.b.c.*         - 10.0.0.*
  #    a.b.c.d/w.x.y.z - 10.0.0.0/255.255.224.0 (standard format)
  #    a.b.c.d/w.x.y.z - 10.0.0.0/0.0.16.255    (cisco format)
  #    a.b.c.d-z       - 10.1.2.0-12
  #    a.b.c-x.*       - 10.0.0-3.*
  #    a.b.c-x.d       - 10.0.0-3.0
  # 2nd wether or not to return an error message or nothing 
  #    default is to return nothing on error
  # 3rd is max number IPs to return 
  #    default max is 65536 and can not be raised at this time
  my ($ip, $return_error, $max_ip) = @_;
  my @msg = ();
  my $err = '';
  $max_ip = $max_ip || 65536;
  my $a, $b, $c, $d, $sub_a, $sub_b, $sub_c, $sub_d, $num_ip,
      $nm, $d_s, $d_f, $c_s, $c_f, @msg, $err, $num_sub,
      $start_sub, $count_sub;
  # lets start now...
  # does it look just like a single IP address?
  if ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
    print "- DEBUG ($$): x.x.x.x format $ip\n" if ($opt_d);
    $a = $1; $b = $2; $c = $3; $d = $4;
    if ( $a > 255 or $a < 0 or $b > 255 or $b < 0 or $c > 255 or $c < 0 or 
         $d > 255 or $d < 0) {
      $err = "ERROR: Appears to be a bad IP address ($ip)";
    } else {
      push (@msg, $ip);
    }
  # does it look like the format x.x.x.x/n
  } elsif ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/) {
    print "- DEBUG ($$): x.x.x.x/n format $ip\n" if ($opt_d);
    $a = $1; $b = $2; $c = $3; $d = $4; $nm = $5;
    if ( $a > 255 or $a < 0 or $b > 255 or $b < 0 or $c > 255 or $c < 0 or 
         $d > 255 or $d < 0 or $nm > 30 or $nm < 0) {
      $err = "ERROR: Something appears to be wrong ($ip)";
    } else {
      $num_ip = 2**(32-$nm);
      if ($num_ip > $max_ip) {
        $err = "ERROR: Too many IPs returned ($num_ip)";
      } elsif ($num_ip <= 256) {
        $num_sub = 256/$num_ip;
        SUBNET: for $count_sub (0..($num_sub - 1)) {
          $start_sub = $count_sub * $num_ip;
          if ($d > $start_sub and $d < ($start_sub + $num_ip)) {
            $d = $start_sub;
            last SUBNET;
          }
        }
        for $d ($d..($d + $num_ip - 1)) {
          $ip = "$a.$b.$c.$d"; push (@msg, $ip);
        }
      } elsif ($num_ip <= 65536) {
        $num_sub = 256/($num_ip/256); $num_ip = $num_ip/256;
        SUBNET: for $count_sub (0..($num_sub - 1)) {
          $start_sub = $count_sub * $num_ip;
          if ($c > $start_sub and $c < ($start_sub + $num_ip)) {
            $c = $start_sub;
            last SUBNET;
          }
        }
        for $c ($c..($c + $num_ip - 1)) {
          for $d (0..255) {
            $ip = "$a.$b.$c.$d"; push (@msg, $ip);
          }
        }
      }
    }
  # does it look like the format x.x.x.x-y
  } elsif ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\-(\d{1,3})$/) {
    print "- DEBUG ($$): x.x.x.x-y format $ip\n" if ($opt_d);
    $a = $1; $b = $2; $c = $3; $d_s = $4; $d_f = $5;
    if ( $d_f > 255 or $d_s > 255 or $d_s < 0 or $d_f < 0 or $a < 0 or 
         $a > 255 or $b < 0 or $b > 255 or $c < 0 or $c > 255 ) {
      $err = "ERROR: Something appears to be wrong ($ip).";
    } elsif ($d_f < $d_s) {
      LOOP: for $d ($d_f .. $d_s) {
        if ($#msg > $max_ip) { 
          $err = "ERROR: Too many IPs returned ($#msg+)"; 
          last LOOP;
        }
        $ip = "$a.$b.$c.$d"; push (@msg, $ip);
      }
      # $err = "Sorry, we don't count backwards.";
    } elsif ($d_f == $d_s) {
      $ip = "$a.$b.$c.$d_s"; push (@msg, $ip);
    } else {
      LOOP: for $d ($d_s .. $d_f) {
        if ($#msg > $max_ip) { 
          $err = "ERROR: Too many IPs returned ($#msg+)"; 
          last LOOP;
        }
        $ip = "$a.$b.$c.$d"; push (@msg, $ip);
      }
    }
      # does it look like the format x.x.x-y.*
  } elsif ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\-(\d{1,3})\.(.*)$/) {
    print "- DEBUG ($$): x.x.x-y.* format $ip\n" if ($opt_d);
    $a = $1; $b = $2; $c_s = $3; $c_f = $4; $d = $5;
    if ( $c_f > 255 or $c_s > 255 or $c_s < 0 or $c_f < 0 or 
         $a < 0 or $a > 255 or $b < 0 or $b > 255 or 
         ( ($d < 0 or $d > 255) and $d ne "*") ) {
      $err = "ERROR: Something appears to be wrong ($ip)";
    } elsif ($c_f < $c_s) {
      LOOP: for $c ($c_f .. $c_s) {
        for $d (0..255) {
          if ($#msg > $max_ip) { 
            $err = "ERROR: Too many IPs returned ($#msg+)"; 
            last LOOP;
          }
          $ip = "$a.$b.$c.$d"; push (@msg, $ip);
        }
      }
    } elsif ($c_f == $c_s) {
      $ip = "$a.$b.$c_s.$d"; push (@msg, $ip);
    } else {
      LOOP: for $c ($c_s .. $c_f) {
        for $d (0..255) {
          if ($#msg > $max_ip) { 
            $err = "ERROR: Too many IPs returned ($#msg+)"; 
            last LOOP;
          }
          $ip = "$a.$b.$c.$d"; push (@msg, $ip);
        }
      }
    }
  # does it look like the format x.x.x.*
  } elsif ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\*$/) {
    print "- DEBUG ($$): x.x.x.* format $ip\n" if ($opt_d);
    $a = $1; $b = $2; $c = $3;
    if ( $a < 0 or $a > 255 or $b < 0 or $b > 255 or $c < 0 or $c > 255 ) {
      $err = "ERROR: Something appears to be wrong ($ip)";
    } else {
      LOOP: for $d (0 .. 255) {
        if ($#msg > $max_ip) { 
          $err = "ERROR: Too many IPs returned ($#msg+)"; 
          last LOOP;
        }
        $ip = "$a.$b.$c.$d"; push (@msg, $ip);
      }
    }
  # does it look like the format x.x.x.x/y.y.y.y
  } elsif ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
    print "- DEBUG ($$): x.x.x.x/y.y.y.y format $ip\n" if ($opt_d);
    $a = $1; $b = $2; $c = $3; $d = $4; 
    $sub_a = $5; $sub_b = $6; $sub_c = $7; $sub_d = $8;
    # if it appears to be in "cisco" format, convert it
    if ($sub_a == 0 and $sub_b == 0) {
      $sub_a = 255 - $sub_a; $sub_b = 255 - $sub_b;
      $sub_c = 255 - $sub_c; $sub_d = 255 - $sub_d;
    }
    # check to see if the input looks valid
    if ( $a > 255 or $a < 0 or $b > 255 or $b < 0 or $c > 255 or $c < 0 or 
         $d > 255 or $d < 0 or $sub_a > 255 or $sub_a < 0 or
         $sub_b > 255 or $sub_b < 0 or $sub_c > 255 or $sub_c < 0 or 
         $sub_d > 255 or $sub_d < 0 or ($sub_d < 255 and $sub_c != 255 and 
         $sub_b != 255 and $sub_a != 255) or ($sub_d != 0 and 
         $sub_c == 0 and $sub_b < 255 and $sub_a == 255) or 
         ($sub_d != 0 and $sub_c < 255 and $sub_b == 255 and 
         $sub_a == 255)) {
      $err = "ERROR: Something appears to be wrong ($ip)";
    # if it looked valid, but it appears to be an IP, return that IP
    } elsif ($sub_d == 255) {
      $ip = "$a.$b.$c.$d"; push (@msg, $ip);
    # if the range appears to be part of a class C
    } elsif ($sub_d < 255 and $sub_d >= 0 and $sub_c == 255) {
      $num_ip = 256 - $sub_d; $num_sub = 256/$num_ip;
      if ($num_ip > $max_ip) {
        $err = "ERROR: Too many IPs returned ($num_ip)";
      } else {
        SUBNET: for $count_sub (0..($num_sub - 1)) {
          $start_sub = $count_sub * $num_ip;
          if ($d > $start_sub and $d < ($start_sub + $num_ip)) {
            $d = $start_sub;
            last SUBNET;
          }
        }
        LOOP: for $d ($d..($d + $num_ip - 1)) {
          if ($#msg > $max_ip) { 
            $err = "ERROR: Too many IPs returned ($#msg+)"; 
            last LOOP;
          }
          $ip = "$a.$b.$c.$d"; push (@msg, $ip);
        }
      }
      # if the range appears to be part of a class B
    } elsif ($sub_c < 255 and $sub_c >= 0) {
      $num_ip = 256 - $sub_c; $num_sub = 256/$num_ip;
      if ($num_ip > $max_ip) {
        $err = "ERROR: Too many IPs returned ($num_ip)";
      } else {
        SUBNET: for $count_sub (0..($num_sub - 1)) {
          $start_sub = $count_sub * $num_ip;
          if ($c > $start_sub and $c < ($start_sub + $num_ip)) {
            $c = $start_sub;
            last SUBNET;
          }
        }
        LOOP: for $c ($c..($c + $num_ip - 1)) {
          for $d (0..255) {
            if ($#msg > $max_ip) { 
              $err = "ERROR: Too many IPs returned ($#msg+)"; 
              last LOOP;
            }
            $ip = "$a.$b.$c.$d"; push (@msg, $ip);
          }
        }
      }
    }
  } elsif ($ip =~ /[\w\.]+/)  {
    print "- DEBUG ($$): DNS name $ip\n" if ($opt_d);
    my ($name,$aliases,$type,$len,@thisaddr) = gethostbyname($ip);
    my ($a,$b,$c,$d) = unpack('C4',$thisaddr[0]);
    if ($a and $b and $c and $d) {
      if (calculate_ip_range("$a.$b.$c.$d")) {
        push @msg, "$a.$b.$c.$d";
      }
    } else {
      $err = "ERROR: Something appears to be wrong ($ip)";
    }
  # if it doesn't match one of those...
  } else {
    print "- DEBUG ($$): Not Recognised $ip\n" if ($opt_d);
    $err = "ERROR: Something appears to be wrong ($ip)";
  }
  if ($err and $return_error) { 
    return "$err\n"; 
  } elsif (@msg) {
    return @msg;
  } else {
    return;
  }
}

