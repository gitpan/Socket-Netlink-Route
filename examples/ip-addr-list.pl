#!/usr/bin/perl

use strict;
use warnings;

use IO::Socket::Netlink::Route;
use Socket;
use Socket::Netlink qw( :DEFAULT );
use Socket::Netlink::Route qw( :DEFAULT );

my $rtnlsock = IO::Socket::Netlink::Route->new
   or die "Cannot make netlink socket - $!";

my @messages;

$rtnlsock->send_nlmsg( $rtnlsock->new_request(
      nlmsg_type  => RTM_GETADDR, 
      nlmsg_flags => NLM_F_ROOT,

      ifa_family => AF_INET,
) );

$rtnlsock->recv_nlmsgs( \@messages, 2**16 ) or
   die "Cannot recv - $!";

foreach my $message ( @messages ) {
   if( $message->nlmsg_type == NLMSG_ERROR ) {
      $! = -(unpack "i!", $message->nlmsg)[0];
      print "Got error $!\n";
   }
   elsif( $message->nlmsg_type == RTM_NEWADDR ) {
      printf "Got reply type=%d flags=%04x seq=%d pid=%d\n",
         $message->nlmsg_type, $message->nlmsg_flags, $message->nlmsg_seq, $message->nlmsg_pid;

      printf "  family=%d prefixlen=%d flags=%04x scope=%d index=%d; rtattrs:\n",
         $message->ifa_family, $message->ifa_prefixlen, $message->ifa_flags, $message->ifa_scope, $message->ifa_index;

      my $attrs = $message->nlattrs;
      foreach my $name ( sort keys %$attrs ) {
         printf "    %s => %s\n", $name, $attrs->{$name};
      }
   }
}
