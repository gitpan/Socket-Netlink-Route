#!/usr/bin/perl

use strict;
use warnings;

use ExtUtils::H2PM 0.03;

module "Socket::Netlink::Route";

include "sys/socket.h";
include "linux/netlink.h";
include "linux/rtnetlink.h";

use_export;

constant "NETLINK_ROUTE";

constant "RTM_NEWLINK";
constant "RTM_DELLINK";
constant "RTM_GETLINK";
constant "RTM_SETLINK";

structure "struct ifinfomsg",
   with_tail => 1,
   members => [
      ifi_family => member_numeric,
      ifi_type   => member_numeric,
      ifi_index  => member_numeric,
      ifi_flags  => member_numeric,
      ifi_change => member_numeric,
   ];

constant "IFLA_$_" for qw( UNSPEC ADDRESS BROADCAST IFNAME MTU LINK QDISC
   STATS COST PRIORITY MASTER WIRELESS PROTINFO TXQLEN MAP WEIGHT OPERSTATE
   LINKMODE LINKINFO NET_NS_PID IFALIAS );

constant "RTM_NEWADDR";
constant "RTM_DELADDR";
constant "RTM_GETADDR";

structure "struct ifaddrmsg",
   with_tail => 1,
   members => [
      ifa_family    => member_numeric,
      ifa_prefixlen => member_numeric,
      ifa_flags     => member_numeric,
      ifa_scope     => member_numeric,
      ifa_index     => member_numeric,
   ];

constant "IFA_$_" for qw( UNSPEC ADDRESS LOCAL LABEL BROADCAST ANYCAST CACHEINFO );

constant "RTM_NEWROUTE";
constant "RTM_DELROUTE";
constant "RTM_GETROUTE";

structure "struct rtmsg",
   with_tail => 1,
   members => [
      rtm_family   => member_numeric,
      rtm_dst_len  => member_numeric,
      rtm_src_len  => member_numeric,
      rtm_tos      => member_numeric,
      rtm_table    => member_numeric,
      rtm_protocol => member_numeric,
      rtm_scope    => member_numeric,
      rtm_type     => member_numeric,
      rtm_flags    => member_numeric,
   ];

constant "RTN_$_" for qw( UNSPEC UNICAST LOCAL BROADCAST ANYCAST MULTICAST
   BLACKHOLE UNREACHABLE PROHIBIT THROW NAT XRESOLVE );

constant "RTPROT_$_" for qw( UNSPEC REDIRECT KERNEL BOOT STATIC );

constant "RT_SCOPE_$_" for qw( UNIVERSE SITE LINK HOST NOWHERE );

constant "RTM_F_$_" for qw( NOTIFY CLONED EQUALIZE );

constant "RT_TABLE_$_" for qw( UNSPEC DEFAULT MAIN LOCAL );

constant "RTA_$_" for qw( UNSPEC DST SRC IIF OIF GATEWAY PRIORITY PREFSRC
   METRICS MULTIPATH PROTOINFO FLOW CACHEINFO );

write_output $ARGV[0];
