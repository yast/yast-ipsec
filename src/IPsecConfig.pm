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

# map of certificates
# certificates
#  +-> "cert.pem"
#  +-> "DN" = "/foo/bar/baz"
#  \-> "subjectAltName" = "foo@bar"

my %certificates;
my %cacertificates;
my %crls;
my %keys;

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
 # do not read or write anything, just fake connections
 #
BEGIN { $TYPEINFO{enableTestMode} = ["function", "void"]; }
sub enableTestMode()
{
    # TODO
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
    if($fsutil and $fsutil->load()) {
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
	             "FreeSwanUtils->load() => OK\n";
	%settings = %{$fsutil->{'setup'} || {}};

	print STDERR "HAVE CONNS: ", join(", ", $fsutil->conns()), "\n";

	my @conns = $fsutil->conns(exclude => [qw(%default %implicit)]);

	print STDERR "WANT CONNS: ", join(", ", @conns), "\n";

        for my $name (@conns) {
            print STDERR "copy connections += $name\n";
            $connections{$name} = {$fsutil->conn($name)};
	}
	return Boolean(1);
    } else {
	print STDERR "ipsec.conf parsing error: ",
	             $fsutil->errstr(), "\n";
    }
    return Boolean(0);
}

BEGIN { $TYPEINFO{LastError} = ["function", "string"]; }
sub LastError()
{
    return $fsutil->errstr();
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
sub setSettings($)
{
    my $ref = shift;

    print STDERR "IPsecConfig::setSettings({\n";
    for my $key (keys %{$ref}) {
	print STDERR "\t$key => ", $ref->{$key} || '', "\n";

	next unless("".$key =~ /\S+/);
	if("".$ref->{$key} =~ /\S+/) {
	    $settings{$key} = $ref->{$key};
	} else {
	    delete($settings{$key});
	}
    }
    print STDERR "}) called\n";

    y2milestone(%{$ref});
}

# first parameter is a map of strings
BEGIN { $TYPEINFO{setConnections} = ["function", "void" , [ "map", "string", [ "map", "string", "string" ]]]; }
sub setConnections($)
{
    my $ref = shift;

    print STDERR "IPsecConfig::setConnections(\n";
    for my $name (sort keys %{$ref}) {
	print STDERR "$name => {\n";
	for my $key (sort keys %{$ref->{$name}}) {
	    print "\t$key=", $ref->{$name}->{$key}, "\n";
	}
	print STDERR "},\n";

	$connections{$name} = $ref->{$name};
    }
    print STDERR ") called\n";
    y2milestone(%{$_[0]});
}

##
 # delete connection from connection hash
 # @param name of connection
BEGIN { $TYPEINFO{deleteConnection} = ["function", "void", "string" ]; }
sub deleteConnection($)
{
    my $name = shift;
    print STDERR "IPsecConfig::deleteConnection($name) called\n";
    delete $connections{$name};
}

##
 # add a connection to connection hash. The connection might already exist in
 # which case it means to update the connection with new values
 # @param name of connection
 # @param connection hash
BEGIN { $TYPEINFO{addConnection} = ["function", "void", "string", [ "map", "string", "string" ]]; }
sub addConnection($$)
{
    my $name = shift;
    my $ref = shift;

    print STDERR "IPsecConfig::addConnection($name => {";
    for my $key (sort keys %{$ref}) {
	print "\t$key=", $ref->{$key}, "\n";
    }
    print STDERR "}) called\n";
    $connections{$name} = $ref;
}

##
 # Write all ipsec settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write
{
    # TODO
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

#########################
## certificate handling
###################

##
 # get map of certificates
 # @returns connection map
 #
BEGIN { $TYPEINFO{Certificates} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub Certificates()
{
    # TODO
    return \%certificates;
}

##
 # delete a certificate
 # @param name
BEGIN { $TYPEINFO{deleteCertificate} = ["function", "void" , "string" ]; }
sub deleteCertificate($)
{
    # TODO
    my $name = shift;
    delete $certificates{$name};
}

##
 # import a certificate from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCertificate} = ["function", "string", "string" ]; }
sub importCertificate($)
{
    # TODO
    my $filename = shift;
    return _("importing certificates not supported yet");
}

##
 # get map of CA certificates
 # @returns connection map
 #
BEGIN { $TYPEINFO{CACertificates} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub CACertificates()
{
    # TODO
    return \%cacertificates;
}

##
 # delete a CA certificate
 # @param name
BEGIN { $TYPEINFO{deleteCACertificate} = ["function", "void" , "string" ]; }
sub deleteCACertificate($)
{
    # TODO
    my $name = shift;
    delete $cacertificates{$name};
}

##
 # import a CA certificate from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCACertificate} = ["function", "string", "string" ]; }
sub importCACertificate($)
{
    # TODO
    my $filename = shift;
    return _("importing CA certificates not supported yet");
}


##
 # get map of CRLs
 # @returns connection map
 #
BEGIN { $TYPEINFO{CRLs} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub CRLs()
{
    # TODO
    return \%crls;
}

##
 # delete a CRL
 # @param name
BEGIN { $TYPEINFO{deleteCRL} = ["function", "void" , "string" ]; }
sub deleteCRL($)
{
    # TODO
    my $name = shift;
    delete $crls{$name};
}

##
 # import a CRL from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCRL} = ["function", "string", "string" ]; }
sub importCRL($)
{
    # TODO
    my $filename = shift;
    return _("importing CRLs not supported yet");
}

##
 # get map of keys
 # @returns connection map
 #
BEGIN { $TYPEINFO{Keys} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub Keys()
{
    # TODO
    return \%keys;
}

##
 # delete a key
 # @param name
BEGIN { $TYPEINFO{deleteKey} = ["function", "void" , "string" ]; }
sub deleteKey($)
{
    # TODO
    my $name = shift;
    delete $keys{$name};
}

##
 # import a Key from file
 # @param filename to import
 # @param passwort (maybe empty, means no password)
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importKey} = ["function", "string", "string", "string" ]; }
sub importKey($)
{
    # TODO
    my $filename = shift;
    my $password = shift;
    return _("importing keys not supported yet");
}

##
 # Look at PKCS#12 file and extract it's components
 # @param path to p12 file
 # @param password for the file
 # @return hash with keys cacerts, certs, key or key error with error string
BEGIN { $TYPEINFO{prepareImportP12} = ["function", [ "map", "string", "string" ], "string", "string" ]; }
sub prepareImportP12($$)
{
    # TODO
    my $file = shift;
    my $password = shift;
    # return ( "error" => "not yet implemented" );
    return { "cacert" => "FIXME", "cert" => "FIXME", "key" => "FIXME" };
}

##
 # really import the file that was prepared via PrepareImportP12()
 # @return undef or error string
BEGIN { $TYPEINFO{importPreparedP12} = ["function", "void" ]; }
sub importPreparedP12()
{
    # TODO
    return "importing PKCS#12 not yet implemented";
}


# EOF
# vim: sw=4
