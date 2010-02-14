#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2010 -- leonerd@leonerd.org.uk

package IO::Socket::Netlink::Route;

use strict;
use warnings;
use base qw( IO::Socket::Netlink );

our $VERSION = '0.01';

use Carp;

use Socket::Netlink::Route;

__PACKAGE__->register_protocol( NETLINK_ROUTE );

=head1 NAME

C<IO::Socket::Netlink::Route> - Object interface to C<NETLINK_ROUTE> netlink
protocol sockets

=head1 DESCRIPTION

This subclass of L<IO::Socket::Netlink> implements the C<NETLINK_ROUTE>
protocol. This protocol allows communication with the Linux kernel's
networking stack, allowing querying or modification of interfaces, addresses,
routes, and other networking properties.

This module is currently a work-in-progress, and this documentation is fairly
minimal. The reader is expected to be familiar with C<NETLINK_ROUTE>, as it
currently only gives a fairly minimal description of the Perl-level wrapping
of the kernel level concepts. For more information see the documentation in
F<rtnetlink(7)>.

=cut

sub new
{
   my $class = shift;
   $class->SUPER::new( Protocol => NETLINK_ROUTE, @_ );
}

sub message_class
{
   return "IO::Socket::Netlink::Route::_Message";
}

=head1 MESSAGE CLASSES

Each message type falls into one of the following subclasses, chosen by the
value of the C<nlmsg_type> field. Each subclass provides access to the field
headers of its message body, and netlink attributes.

=cut

package IO::Socket::Netlink::Route::_Message;

use base qw( IO::Socket::Netlink::_Message );

use Carp;

use Socket::Netlink::Route qw( :DEFAULT );

# Route messages could have different body structures, depending on the
# message type. What we'll do is switch up to a more specific subclass when
# the nlmsg_type is set

my %type2pkg;

sub register_nlmsg_type
{
   my $class = shift;
   my ( $type ) = @_;
   $type2pkg{$type} = $class;
}

sub nlmsg_type
{
   my $self = shift;
   my $nlmsg_type = $self->SUPER::nlmsg_type( @_ );

   if( @_ ) {
      my $pkg = $type2pkg{$nlmsg_type};
      bless $self, $pkg if $pkg;
   }

   return $nlmsg_type;
}

sub   pack_nlattr_mac { join "", map chr(hex $_), split /:/, $_[1] }
sub unpack_nlattr_mac { join ":", map sprintf("%02x",ord($_)), split //, $_[1] }

sub   pack_nlattr_dottedhex { die "TODO" }
sub unpack_nlattr_dottedhex { "0x" . join ".", map sprintf("%02x",ord($_)), split //, $_[1] }

use Socket6 qw( inet_ntop );

sub pack_nlattr_protaddr { die "TODO" }
sub unpack_nlattr_protaddr
{
   my ( $self, $addr ) = @_;
   eval { defined $self->ifa_family and inet_ntop( $self->ifa_family, $addr ) }
      or $self->unpack_nlattr_dottedhex( $addr );
}

package IO::Socket::Netlink::Route::_IfinfoMsg;

use base qw( IO::Socket::Netlink::Route::_Message );
use Socket::Netlink::Route qw( :DEFAULT pack_ifinfomsg unpack_ifinfomsg );
use Socket qw( AF_UNSPEC );

=head2 IfinfoMsg

Relates to a network interface. Used by the following message types

=over 4

=item * RTM_NEWLINK

=item * RTM_DELLINK

=item * RTM_GETLINK

=back

=cut

__PACKAGE__->register_nlmsg_type( $_ )
   for RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK;

=pod

Provides the following header field accessors

=over 4

=item * ifi_family

=item * ifi_type

=item * ifi_index

=item * ifi_flags

=item * ifi_change

=back

=cut

__PACKAGE__->is_header(
   data   => "nlmsg",
   fields => [
      [ ifi_family => "decimal" ],
      [ ifi_type   => "decimal" ],
      [ ifi_index  => "decimal" ],
      [ ifi_flags  => "hex"     ],
      [ ifi_change => "hex"     ],
      [ ifinfo     => "bytes" ],
   ],
   pack   => \&pack_ifinfomsg,
   unpack => \&unpack_ifinfomsg,
);

=pod

Provides the following netlink attributes

=over 4

=item * address => STRING

=item * broadcast => STRING

=item * ifname => STRING

=item * mtu => INT

=item * qdisc => STRING

=item * txqlen => INT

=item * operstate => INT

=item * linkmode => INT

=back

=cut

__PACKAGE__->has_nlattrs(
   "ifinfo",
   address   => [ IFLA_ADDRESS,   "mac" ],
   broadcast => [ IFLA_BROADCAST, "mac" ],
   ifname    => [ IFLA_IFNAME,    "asciiz" ],
   mtu       => [ IFLA_MTU,       "u32" ],
   qdisc     => [ IFLA_QDISC,     "asciiz" ],
   txqlen    => [ IFLA_TXQLEN,    "u32" ],
   operstate => [ IFLA_OPERSTATE, "u8" ],
   linkmode  => [ IFLA_LINKMODE,  "u8" ],
);

package IO::Socket::Netlink::Route::_IfaddrMsg;

use base qw( IO::Socket::Netlink::Route::_Message );
use Socket::Netlink::Route qw( :DEFAULT pack_ifaddrmsg unpack_ifaddrmsg );

=head2 IfaddrMsg

Relates to an address present on an interface. Used by the following message
types

=over 4

=item * RTM_NEWADDR

=item * RTM_DELADDR

=item * RTM_GETADDR

=back

=cut

__PACKAGE__->register_nlmsg_type( $_ )
   for RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR;

=pod

Provides the following header field accessors

=over 4

=item * ifa_family

=item * ifa_prefixlen

=item * ifa_flags

=item * ifa_scope

=item * ifa_index

=back

=cut

__PACKAGE__->is_header(
   data   => "nlmsg",
   fields => [
      [ ifa_family    => "decimal" ],
      [ ifa_prefixlen => "decimal" ],
      [ ifa_flags     => "hex"     ],
      [ ifa_scope     => "decimal" ],
      [ ifa_index     => "decimal" ],
      [ ifaddr        => "bytes" ],
   ],
   pack   => \&pack_ifaddrmsg,
   unpack => \&unpack_ifaddrmsg,
);

=pod

Provides the following netlink attributes

=over 4

=item * address => STRING

=item * local => STRING

=item * label => STRING

=item * broadcast => STRING

=item * anycast => STRING

=back

=cut

__PACKAGE__->has_nlattrs(
   "ifaddr",
   address   => [ IFA_ADDRESS,   "protaddr" ],
   local     => [ IFA_LOCAL,     "protaddr" ],
   label     => [ IFA_LABEL,     "asciiz" ],
   broadcast => [ IFA_BROADCAST, "protaddr" ],
   anycast   => [ IFA_ANYCAST,   "protaddr" ],
);

package IO::Socket::Netlink::Route::_RtMsg;

use base qw( IO::Socket::Netlink::Route::_Message );
use Socket::Netlink::Route qw( :DEFAULT pack_rtmsg unpack_rtmsg );

=head2 RtMsg

Relates to a routing table entry. Used by the following message types

=over 4

=item * RTM_NEWROUTE

=item * RTM_DELROUTE

=item * RTM_GETROUTE

=back

=cut

__PACKAGE__->register_nlmsg_type( $_ )
   for RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE;

=pod

Provides the following header field accessors

=over 4

=item * rtm_family

=item * rtm_dst_len

=item * rtm_src_len

=item * rtm_tos

=item * rtm_table

=item * rtm_protocol

=item * rtm_scope

=item * rtm_type

=item * rtm_flags

=back

=cut

__PACKAGE__->is_header(
   data   => "nlmsg",
   fields => [
      [ rtm_family   => "decimal" ],
      [ rtm_dst_len  => "decimal" ],
      [ rtm_src_len  => "decimal" ],
      [ rtm_tos      => "hex" ],
      [ rtm_table    => "decimal" ],
      [ rtm_protocol => "decimal" ],
      [ rtm_scope    => "decimal" ],
      [ rtm_type     => "decimal" ],
      [ rtm_flags    => "hex" ],
      [ rtm          => "bytes" ],
   ],
   pack   => \&pack_rtmsg,
   unpack => \&unpack_rtmsg,
);

=pod

Provides the following netlink attributes

=over 4

=item * dst => STRING

=item * src => STRING

=item * iif => INT

=item * oif => INT

=item * gateway => STRING

=item * priority => INT

=item * metrics => INT

=back

=cut

__PACKAGE__->has_nlattrs(
   "rtm",
   dst      => [ RTA_DST,      "protprefix_dst" ],
   src      => [ RTA_SRC,      "protprefix_src" ],
   iif      => [ RTA_IIF,      "u32" ],
   oif      => [ RTA_OIF,      "u32" ],
   gateway  => [ RTA_GATEWAY,  "protaddr" ],
   priority => [ RTA_PRIORITY, "u32" ],
   metrics  => [ RTA_METRICS,  "u32" ],
);

use Socket6 qw( inet_ntop );

sub pack_nlattr_protaddr { die "TODO" }
sub unpack_nlattr_protaddr
{
   my ( $self, $addr ) = @_;
   eval { defined $self->rtm_family and inet_ntop( $self->rtm_family, $addr ) }
      or $self->unpack_nlattr_dottedhex( $addr );
}

sub pack_nlattr_protprefix_dst { die "TODO" }
sub unpack_nlattr_protprefix_dst
{
   my ( $self, $addr ) = @_;
   sprintf "%s/%d", $self->unpack_nlattr_protaddr( $addr ), $self->rtm_dst_len;
}

sub pack_nlattr_protprefix_src { die "TODO" }
sub unpack_nlattr_protprefix_src
{
   my ( $self, $addr ) = @_;
   sprintf "%s/%d", $self->unpack_nlattr_protaddr( $addr ), $self->rtm_src_len;
}

# Keep perl happy; keep Britain tidy
1;

__END__

=head1 SEE ALSO

=over 4

=item *

L<Socket::Netlink::Route> - interface to Linux's C<NETLINK_ROUTE> netlink
socket protocol

=item *

L<IO::Socket::Netlink> - Object interface to C<AF_NETLINK> domain sockets

=item *

F<rtnetlink(7)> - rtnetlink, NETLINK_ROUTE - Linux IPv4 routing socket

=back

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>
