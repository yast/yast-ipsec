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
use warnings;
use diagnostics;
use Locale::gettext;
use POSIX;     # Needed for setlocale()
use File::Temp qw(tempdir);
use File::Path;

use lib "/usr/share/YaST2/modules"; #### FIXME!!!
use FreeSwanUtils;
use FreeSwanCerts;

#use ycp;
use YaST::YCP qw(:LOGGING Boolean);
#YaST::YCP::Import ("SCR");

setlocale(LC_MESSAGES, "");
textdomain("ipsec");

my $fsutil;
my %connections;
my %settings;

# map of certificates
# certificates
#  +-> "cert.pem"
#    +-> "DN" = "/foo/bar/baz"
#    \-> "subjectAltName" = "foo@bar"

my $openssl;
my %certificates;
my %cacertificates;
my %crls;
my %keys;

my $temp_tree;
my %imports;

#
# NOTE: debug for developement only!
#       we use own y2logger helper
#
my $DEBUG = 1;
sub debug {
    if($DEBUG) {
	my ($package, $filename, $line) = caller;
	my $subroutine = (caller(1))[3];
	my $level = 1;	# level 1 is y2milestone

	YaST::YCP::y2_logger($level, "Perl", $filename,
	                     $line, $subroutine, join("", @_));
   }
}

sub _ {
    return gettext($_[0]);
}

our %TYPEINFO;

BEGIN
{
    $DEBUG = 1 if(exists($ENV{'Y2DEBUG_IPSEC'}));

    $fsutil = new FreeSwanUtils();
    $openssl = new OpenCA::OpenSSL(SHELL => "/usr/bin/openssl");

    # FIXME: it does not exists per default...
    unless(-d "/etc/ipsec.d/certs") {
        mkdir("/etc/ipsec.d/certs", 0755);
    }

    cleanupImport();

    # FIXME: cleanup it!!
    $temp_tree = tempdir("/tmp/yast2-ipsec-XXXXXX", CLEANUP => 1);
}

END
{
    cleanup();
}

##
 # do not read or write anything, just fake connections
 #
BEGIN { $TYPEINFO{enableTestMode} = ["function", "void"]; }
sub enableTestMode()
{
    # TODO
}

## FIXME: error handling
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
    debug "FreeSwanUtils => ",  $fsutil ? "OK" : "ERR";
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
	debug "FreeSwanUtils->load() => OK";
	%settings = %{$fsutil->{'setup'} || {}};

	debug "HAVE CONNS: ", join(", ", $fsutil->conns());

	my @conns = $fsutil->conns(exclude => [qw(%default %implicit)]);

	debug "WANT CONNS: ", join(", ", @conns);

        for my $name (@conns) {
            debug "copy connections += $name";
            $connections{$name} = {$fsutil->conn($name)};
	}
    } else {
	debug "ipsec.conf parsing error: ", $fsutil->errstr();
    }

    if($openssl) {
	%crls           = FreeSwanCerts::list_CRLs($openssl);
	%certificates   = FreeSwanCerts::list_CERTs($openssl);
	%cacertificates = FreeSwanCerts::list_CAs($openssl);
	y2milestone(%certificates);
    } else {
	debug "HUH? No openssl-shell instance?";
    }
    return Boolean(1);
}

##
 # Write all ipsec settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write
{
    my @errors = FreeSwanCerts::commit_scheduled_file_operations();
    return Boolean(1);
}

BEGIN { $TYPEINFO{LastError} = ["function", "string"]; }
sub LastError()
{
    return $fsutil->errstr();
}

BEGIN { $TYPEINFO{Settings} = ["function", [ "map", "string", "string" ]]; }
sub Settings()
{
    debug "{";
    for my $key (sort keys %settings) {
	my $val = $settings{$key};
	debug "\t$key=$val";
    }
    debug "}";
    return \%settings;
}

# first parameter is a map of something
BEGIN { $TYPEINFO{setSettings} = ["function", "void" , [ "map", "string", "string" ]]; }
sub setSettings($)
{
    my $ref = shift;

    debug "{";
    for my $key (keys %{$ref}) {
	debug "\t$key => ", $ref->{$key} || '';

	next unless("".$key =~ /\S+/);
	if("".$ref->{$key} =~ /\S+/) {
	    $settings{$key} = $ref->{$key};
	} else {
	    delete($settings{$key});
	}
    }
    debug "}";
}


BEGIN { $TYPEINFO{Connections} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub Connections()
{
    debug "{";
    for my $name (sort keys %connections) {
	my $conn = $connections{$name};
	debug "\tconn ", $name, " => {";
	for my $key (sort keys %{$conn}) {
	    my $val = $conn->{$key};
	    debug "\t\t$key=$val";
	}
	debug "\t},";
    }
    debug "}";
    return \%connections;
}

##
 # delete connection from connection hash
 # @param name of connection
BEGIN { $TYPEINFO{deleteConnection} = ["function", "void", "string" ]; }
sub deleteConnection($)
{
    my $name = shift;
    debug "name => $name";
    delete $connections{$name};
}

##
 # check whether a user entered connection name is valid for ipsec.conf
 # @return undef if ok, error string otherwise
 #
BEGIN { $TYPEINFO{validConnectionName} = ["function", "string", "string" ]; }
sub validConnectionName($)
{
    my $name = shift;

    return _("A connection name may not contain spaces") if $name =~ / /;

    # TODO: more checks
    
    return undef;
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

    debug "$name => {";
    for my $key (sort keys %{$ref}) {
	debug "\t$key=", $ref->{$key};
    }
    debug "}";
    $connections{$name} = $ref;
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
 # get a name for certificate, ccacertificate, crl or key
 # @param prefix, e.g. "cert"
 # @param suffix, e.g. ".pem"
 # @param hash reference, e.g. \%certificates
 # @return $prefix$somenumber.$suffix
sub get_free_key_for_hash($$$)
{
    my $prefix = shift;
    my $suffix = shift;
    my $href = shift;
    my $idx = 0;
    my $saveas = $prefix.$suffix;
    while (exists $href->{$saveas})
    {
	$idx++;
	$saveas = $prefix.$idx.$suffix
    }
    return $saveas;
}

##
 # import a certificate from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCertificate} = ["function", "string", "string" ]; }
sub importCertificate($)
{
    my $filename = shift;
    my $href = parse_cert($openssl, $filename);

    return _("importing certificate failed") unless (defined $href);

    my $saveas = get_free_key_for_hash("cert", ".pem", \%certificates);
    return _("importing certificate failed") unless (defined $saveas);

    FreeSwanCerts::save_certificate_as($filename, $saveas);
    $certificates{$saveas} = $href;

    return undef;
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
    my $filename = shift;
    my $href = parse_cert($openssl, $filename);

    if(!defined $href)
    {
	return _("importing CA certificate failed"); # FIXME
    }

    my $idx = 0;
    while (exists $cacertificates{"cacert".$idx.".pem"})
    {
	$idx++;
    }
    $cacertificates{"cacert".$idx.".pem"} = $href;

    return undef;
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
    my $filename = shift;
    my $href = parse_crl($openssl, $filename);

    if(!defined $href)
    {
	return _("importing CRL failed"); # FIXME
    }

    my $idx = 0;
    while (exists $crls{"crl".$idx.".pem"})
    {
	$idx++;
    }
    $crls{"crl".$idx.".pem"} = $href;

    return undef;
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
    my $filename = shift;
    my $password = shift;
    my $href = parse_key($openssl, $filename, $password);

    if(!defined $href)
    {
	return _("importing key failed"); # FIXME
    }

    my $idx = 0;
    while (exists $keys{"key".$idx.".pem"})
    {
	$idx++;
    }
    $keys{"key".$idx.".pem"} = $href;

    return undef;
}

##
 # Look at PKCS#12 file and extract it's components
 # @param path to p12 file
 # @param password for the file
 # @return hash with keys cacerts, certs, key or key error with error string
BEGIN { $TYPEINFO{prepareImportP12} = ["function", [ "map", "string", "string" ], "string", "string" ]; }
sub prepareImportP12($$;$)
{
    # TODO
    my $file = shift;
    my $password = shift;
    #
    # return ( "error" => "not yet implemented" );
    #
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

##
 # cancel an import that was started with prepareImportP12. Delete any
 # temporary files.
 #
BEGIN { $TYPEINFO{cancelPreparedP12} = ["function", "void" ]; }
sub cancelPreparedP12()
{
}

BEGIN { $TYPEINFO{FinishImport} = ["function", "void" ]; }
sub finishImport()
{
}

BEGIN { $TYPEINFO{cleanupImport} = ["function", "void" ]; }
sub cleanupImport()
{
    # FIXME: delete any temp files, ...
    %imports = (
	'CACERTIFICATES' => {},
	'CERTIFICATES'   => {},
	'CRLS'           => {},
	'KEYS'           => {},
	'CONFIGS'        => {},
    );
}

BEGIN { $TYPEINFO{cleanup} = ["function", "void" ]; }
sub cleanup()
{
    debug "starting cleanup";
    cleanupImport();
    if($temp_tree) {
	rmtree($temp_tree);
	$temp_tree = undef;
    }
    debug "finished cleanup";
}

##
 # GUI callback function
 #  Parameter:	prompt string
 #  Returns:	password or undef for skip
 #
sub passwordPrompt($)
{
    return undef;
}

# EOF
# vim: sw=4
