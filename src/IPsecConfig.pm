#! /usr/bin/perl -w
# File:		modules/IPsec.pm
# Package:	Configuration of ipsec
# Summary:	IPsec settings, input and output functions
# Authors:	Ludwig Nussel <lnussel@suse.de>
#
# $Id$
#
# Representation of the configuration of ipsec.
# Input and output routines.


package IPsecConfig;

use strict;

use ycp;
use YaST::YCP qw(Boolean);

use Locale::gettext;
use POSIX;     # Needed for setlocale()

use lib "/usr/share/YaST2/modules"; #### FIXME!!!
use FreeSwanUtils;

YaST::YCP::Import ("SCR");

setlocale(LC_MESSAGES, "");
textdomain("ipsec");

my $fsutil;
my %connections;
my %settings;

sub _ {
    return gettext($_[0]);
}

our %TYPEINFO;

BEGIN
{
    $fsutil = new FreeSwanUtils();
    print STDERR "new FreeSwanUtils() => ", $fsutil ? "OK" : "ERR", "\n";
}

##
 # Read all ipsec settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read
{
#    my $ref = SCR::Read('.etc.ipsec.conf');
#
#    return Boolean(0) if(ref($ref) ne 'HASH');
#
#    %settings = %{$ref->{"config setup"}};
#
#    delete $ref->{"config setup"};
#
#    %connections = %{$ref};
#
    print STDERR "IPsecConfig::Read() FreeSwanUtils => ",
                 $fsutil ? "OK" : "ERR", "\n";
    %settings = ();
    %connections = ();
    if($fsutil and $fsutil->load_config()) {
	# FIXME: access methods
	#
	# blessed  $config = {
	#   'version' => "2.0",
	#   'include' => [
	#	'incl'	=> 'ipsec.*.conf',     # include glob
	#	'file'	=> '/etc/ipsec.conf',  # included from
	#	'list'	=> [                   # expanded glob
	#	    '/etc/ipsec.foo.conf',
	#           '/etc/ipsec.bar.conf',
	#      ]
	#   ],
	#   'setup' => {
	#	'nat_traversal'	=> 'yes'
	#	'rp_filter'	=> '%unchanged'
	#   },
	#   'conn'      => {
	#       '%default' => {
	#	    'file'    => '/etc/ipsec.conf',
	#           'data'    => {
	#		'auto'	=> 'ignore',
	#           }
	#       },
	#	'roadwarrior' => {
	#	    'file'    => '/etc/ipsec.conf',
	#           'data'    => {
	#		'auto'	=> 'start',
	#		'right' => '%defaultroute',
	#           }
	#	}
	#   }
	# };
	#
	print STDERR "IPsecConfig::Read() ",
	             "FreeSwanConfig->load_config() => OK\n";
	%settings = %{$fsutil->{'setup'}};
	for my $name (keys %{$fsutil->{'conn'} || {}}) {
	    next unless(exists($fsutil->{'conn'}->{$name}->{'data'}));
	    print STDERR "connections += $name\n";
	    $connections{$name} = $fsutil->{'conn'}->{$name}->{'data'};
	}
	return Boolean(1);
    } else {
	print STDERR "ipsec.conf parsing error: ",
	             $fsutil->errstr(), "\n";
    }
    return Boolean(0);
}

BEGIN { $TYPEINFO{Connections} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub Connections()
{
    print STDERR "IPsecConfig::Connections() => {\n";
    for my $name (sort keys %connections) {
	my $conn = $connections{$name};
	print STDERR "\tconn ", $name, " => {\n";
	for my $key (sort keys %{$conn}) {
	    my $val = $conn->{$key};
	    print STDERR "\t\t$key=$val\n";
	}
	print STDERR "\t},\n";
    }
    print STDERR "}\n";
    return \%connections;
}

BEGIN { $TYPEINFO{Settings} = ["function", [ "map", "string", "string" ]]; }
sub Settings()
{
    print STDERR "IPsecConfig::Settings() => {\n";
    for my $key (sort keys %settings) {
	my $val = $settings{$key};
	print STDERR "\t$key=$val\n";
    }
    print STDERR "}\n";
    return \%settings;
}

##
 # Write all ipsec settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write
{
    return Boolean(1);
}

# EOF
# vim: sw=4
