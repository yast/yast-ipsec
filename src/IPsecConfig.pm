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

	print STDERR "HAVE CONNS: ", join(", ", $fsutil->conns()), "\n";

	my @conns = $fsutil->conns(exclude => [qw(%default %implicit)]);

	print STDERR "WANT CONNS: ", join(", ", @conns), "\n";

        for my $name (@conns) {
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

# first parameter is a map of something
BEGIN { $TYPEINFO{setSettings} = ["function", "void" , [ "map", "string", "string" ]]; }
sub setSettings()
{
    y2milestone(%{$_[0]});
}

# first parameter is a map of strings
BEGIN { $TYPEINFO{setConnections} = ["function", "void" , [ "map", "string", [ "map", "string", "string" ]]]; }
sub setConnections()
{
    y2milestone(%{$_[0]});
}

##
 # delete connection from connection hash
 # @param name of connection
BEGIN { $TYPEINFO{deleteConnection} = ["function", "void", "string" ]; }
sub deleteConnection()
{
    my $name = shift;
    delete $connections{$name};
}

##
 # add a connection to connection hash. The connection might already exist in
 # which case it means to update the connection with new values
 # @param name of connection
 # @param connection hash
BEGIN { $TYPEINFO{addConnection} = ["function", "void", "string", [ "map", "string", "string" ]]; }
sub addConnection()
{
    my $name = shift;
    my $ref = shift;
    $connections{$name} = $ref;
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

BEGIN { $TYPEINFO{newDefaultConnection} = ["function", [ "map", "string", "string" ]]; }
sub newDefaultConnection()
{
    my %conn = (
	"left" => "%defaultroute",
	"leftrsasigkey" => "%cert",
	"rightrsasigkey" => "%cert",
	"keyingtries" => "3",
	"auto" => "ignore",
	"esp" => "aes,3des",
	"pfs" => "yes",
    );
    
    return \%conn;
}

##
 # Create new Roadwarrior default connection
 # @return connection map
BEGIN { $TYPEINFO{newRoadWarriorConnection} = ["function", [ "map", "string", "string" ]]; }
sub newRoadWarriorConnection()
{
    my $conn = newDefaultConnection();

    $conn->{"left"} = "%defaultroute";
    $conn->{"right"} = "%any";
    $conn->{"auto"} = "add";

    return $conn;
}

# EOF
# vim: sw=4
