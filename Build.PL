use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
   module_name => 'Socket::Netlink::Route',
   requires => {
      'Socket::Netlink' => '0.03',
   },
   recommends => {
      'Socket6' => 0,
   },
   configure_requires => {
      'Module::Build' => 0,
   },
   build_requires => {
      'ExtUtils::H2PM' => '0.04',
      'Module::Build' => 0,
      'Test::More' => 0,
   },
   license => 'perl',
   create_makefile_pl => 'traditional',
   create_license => 1,
   create_readme  => 1,
);

$build->create_build_script;
