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
#
# NOTE: debug for developement only!
#       we use own y2logger helper
#
my $DEBUG;
BEGIN {
    #
    # Some perl modules writes to STDERR while
    # they are imported / destroyed...
    # This breaks the output of the ncurses UI.
    #
    $DEBUG = 0;
    if(exists($ENV{'Y2DEBUG'}) or exists($ENV{'Y2DEBUG_IPSEC'})) {
	$DEBUG = 1;
    }
    open(STDERR, ">", "/dev/null") unless($DEBUG);
    $SIG{'PIPE'} = 'IGNORE';
}

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
use Date::Calc qw (Parse_Date Date_to_Time);

use YaST::YCP qw(:LOGGING Boolean);
YaST::YCP::Import ("IPsecPopups");
YaST::YCP::Import ("Popup");

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

my %cacertificates;
my %certificates;
my %crls;
my %keys;
my %deleted;

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
    debug "FreeSwanUtils => ",  $fsutil ? "OK" : "ERR";
    %settings = ();
    %connections = ();
    if($fsutil and $fsutil->load()) {
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

    # FIXME: skip duplicates:
    %cacertificates = FreeSwanCerts::list_CAs();
    if(-d "/etc/ipsec.d/certs") {
    %certificates   = FreeSwanCerts::list_CERTs();
    }
    %crls           = FreeSwanCerts::list_CRLs();
    %keys           = FreeSwanCerts::list_KEYs();
    #
    # FIXME: Lookup passwd's for keys in /etc/ipsec.secrets ??
    #
    #y2milestone(%certificates);

    return Boolean(1);
}

##
 # Write all ipsec settings
 # opens popups on error
 # @return true on success
 #
BEGIN { $TYPEINFO{Write} = ["function", "boolean"]; }
sub Write
{
    # it does not exists per default...
    unless(-d "/etc/ipsec.d/certs") {
        mkdir("/etc/ipsec.d/certs", 0755);
    }

    #
    # Save FreeS/WAN config
    #
    my @conns = $fsutil->conns(exclude => [qw(%default %implicit)]);
    for my $name (@conns) {
	unless(exists($connections{$name})) {
	    $fsutil->conn_delete($name);
	}
    }
    for my $name (keys %connections) {
	$fsutil->conn($name, %{$connections{$name}});
    }

    if($fsutil and !$fsutil->save())
    {
	Popup::Error(_("Error saving IPsec config:")."\n"
	             . $fsutil->errstr());
	return Boolean(0);
    }

    #
    # Save FreeS/WAN secrets
    #
    #TODO:


    #
    # Delete scheduled files
    #
    for my $file (keys %deleted) {
	if(length($file) and -f $file) {
	    debug "deleting file $file";
	    unlink($file);
	}
    }

    #
    # Write new CAs, CRLs, CERTs, KEYs
    #
    for my $file (keys %cacertificates) {
	my $href = $cacertificates{$file};
	my $_new = $href->{'NEW'} || 0;

	debug "cacertificates($file): NEW=$_new";
	next unless($_new and $_new == 2); # approved

	$file =~ s/.*\///;
	$file = $FreeSwanCerts::DEFS{'ipsec_cacerts'}."/$file";

	my $err = write_pem_data($file, $href->{'data'}, 0600);
	if(defined($err)) {
	    Popup::Error(sprintf(_("Can't write file %s: %s"),
	                           $file, $err)."\n");
	    return Boolean(0);
	} else {
	    debug "write_pem_data($file) SUCCESS";
	}
    }

    for my $file (keys %certificates) {
    	my $href = $certificates{$file};
	my $_new = $href->{'NEW'} || 0;

	debug "certificates($file): NEW=$_new";
	next unless($_new and $_new == 2); # approved

	$file =~ s/.*\///;
	$file = $FreeSwanCerts::DEFS{'ipsec_certs'}."/$file";

	my $err = write_pem_data($file, $href->{'data'}, 0600);
	if(defined($err)) {
	    Popup::Error(sprintf(_("Can't write file %s: %s"),
	                           $file, $err)."\n");
	    return Boolean(0);
	} else {
	    debug "write_pem_data($file) SUCCESS";
	}
    }

    for my $file (keys %crls) {
    	my $href = $crls{$file};
	my $_new = $href->{'NEW'} || 0;

	debug "crls($file): NEW=$_new";
	next unless($_new and $_new == 2); # approved

	$file =~ s/.*\///;
	$file = $FreeSwanCerts::DEFS{'ipsec_crls'}."/$file";

	my $err = write_pem_data($file, $href->{'data'}, 0600);
	if(defined($err)) {
	    Popup::Error(sprintf(_("Can't write file %s: %s"),
	                           $file, $err)."\n");
	    return Boolean(0);
	} else {
	    debug "write_pem_data($file) SUCCESS";
	}
    }

    for my $file (keys %keys) {
    	my $href = $keys{$file};
	my $_new = $href->{'NEW'} || 0;

	debug "keys($file): NEW=$_new";
	next unless($_new and $_new == 2); # approved

	$file =~ s/.*\///;
	$file = $FreeSwanCerts::DEFS{'ipsec_private'}."/$file";

	my $err = write_pem_data($file, $href->{'data'}, 0600);
	if(defined($err)) {
	    Popup::Error(sprintf(_("Can't write file %s: %s"),
	                           $file, $err)."\n");
	    return Boolean(0);
	} else {
	    debug "write_pem_data($file) SUCCESS";
	}
    }

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

    my $err = $fsutil->is_valid_conn_name($name);
    if($err) {
	return sprintf(_("Connection name '%s' is a reserved / implicit name"),
	               $name) if(2 == $err);
	return _("A connection name can contain only a-z, 0-9, _ and - characters");
    }
    return undef;
}

##
 # add a connection to connection hash. The connection might already exist
 # in which case it means to update the connection with new values
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
 # Create new server connection for roadwarriors
 # @return connection map
BEGIN { $TYPEINFO{newServerConnection} = ["function", [ "map", "string", "string" ]]; }
sub newServerConnection()
{
    my $conn = newDefaultConnection();

    $conn->{"left"} = "%defaultroute";
    $conn->{"right"} = "%any";
    $conn->{"auto"} = "add";

    return $conn;
}

##
 # Create new roadwarrior client connection
 # @return connection map
BEGIN { $TYPEINFO{newClientConnection} = ["function", [ "map", "string", "string" ]]; }
sub newClientConnection()
{
    my $conn = newDefaultConnection();

    $conn->{"left"} = "%defaultroute";
    $conn->{"right"} = "";
    $conn->{"auto"} = "start";

    return $conn;
}

#########################
## certificate handling
###################

##
 # mark file in hash for deletion
 # @param name
 # @param href
sub mark4delete($\%)
{
    my $name = shift;
    my $href = shift;
    if($href and $name and exists($href->{$name})) {
	my $_new = $href->{$name}->{'NEW'} || 0;
	# is absolute file name if not new
	$deleted{$name} = 1 unless($_new);
	delete($href->{$name});
    }
}

##
 # get a unused name for cert, ca, crl or key
 # @param prefix, e.g. "cert_"
 # @param suffix, e.g. ".pem"
 # @param hash reference, e.g. \%certificates
 # @return $prefix$somenumber.$suffix
sub get_free_idx($$\%)
{
    my $prefix = shift;
    my $suffix = shift;
    my $href   = shift;
    my $idx    = 0;
    my $name;
    do {
	$name = $prefix.sprintf("%02d", ++$idx).$suffix;
    } while(exists($href->{$name}));
    return $name;
}

##
 # checks if specified cert/cacert exists in hash
 # @param  cert attribute hash
 # @param  hash we search in
 # @return true if found or false
sub check_new_cert(\%\%)
{
    my $cert = shift;
    my $href = shift;

    for my $idx (keys %{$href}) {
	if(($cert->{'DN'} || '') eq ($href->{$idx}->{'DN'} || '')) {
	    debug "cert dn already exists: ", $cert->{'DN'} || '';
	    return 0;
	}
    }
    debug "cert dn is new: ", $cert->{'DN'} || '';
    return 1;
}

##
 # checks if specified key exists in hash
 # @param  key attribute hash
 # @param  hash we search in
 # @return true if found or false
sub check_new_key(\%\%)
{
    my $key  = shift;
    my $href = shift;

    debug "key is always new :-)";
    return 1; # currently not implemented
}

##
 # checks if specified crl exists in hash and is newer
 # @param  crl attribute hash
 # @param  hash we search in
 # @return name of the crl to override, "" for add or undef
sub check_new_crl(\%\%)
{
    my $crl  = shift;
    my $href = shift;

    return undef unless(defined($crl->{'ISSUER'}) and $crl->{'ISSUER'} ne "");
    for my $idx (keys %{$href}) {
	if($crl->{'ISSUER'} eq $href->{$idx}->{'ISSUER'}) {
	    #
	    # NEXT_UPDATE => 'Apr  1 09:13:05 2004 GMT'
	    #
	    my $cmp = cmp_crl_date_time($crl->{'NEXT_UPDATE'},
	                                $href->{$idx}->{'NEXT_UPDATE'});
	    if(defined($cmp)) {
		if($cmp > 0) {
		    debug "crl is newer: ", $crl->{'ISSUER'};
		    return $idx; # overwrite it
		}
	    }
	    debug "crl issuer exists or older: ", $crl->{'ISSUER'};
	    return undef; # discard crl
	}
    }
    debug "crl issuer is new: ", $crl->{'ISSUER'};
    return "";
}

##
 # compares CRL date-time strings
 # e.g.: "Mar 10 09:13:05 2004 GMT"
 # @param string1
 # @param string2
 # @return the difference or undef on error
sub cmp_crl_date_time
{
    my $str1 = shift;
    my $str2 = shift;
    my @time1 = ($str1 =~ /(\d\d):(\d\d):(\d\d)/);
    my @time2 = ($str2 =~ /(\d\d):(\d\d):(\d\d)/);
    my @date1 = Parse_Date($str1);
    my @date2 = Parse_Date($str2);

    if(3 == scalar(@time1) and 3 == scalar(@time2) and
       3 == scalar(@date1) and 3 == scalar(@date2)) {
       return Date_to_Time(@date1, @time1)
            - Date_to_Time(@date2, @time2);
    }
    return undef;
}

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
    my $name = shift;
    mark4delete($name, %certificates);
}

##
 # get map of CA certificates
 # @returns connection map
 #
BEGIN { $TYPEINFO{CACertificates} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub CACertificates()
{
    return \%cacertificates;
}

##
 # delete a CA certificate
 # @param name
BEGIN { $TYPEINFO{deleteCACertificate} = ["function", "void" , "string" ]; }
sub deleteCACertificate($)
{
    my $name = shift;
    mark4delete($name, %cacertificates);
}

##
 # get map of CRLs
 # @returns connection map
 #
BEGIN { $TYPEINFO{CRLs} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub CRLs()
{
    return \%crls;
}

##
 # delete a CRL
 # @param name
BEGIN { $TYPEINFO{deleteCRL} = ["function", "void" , "string" ]; }
sub deleteCRL($)
{
    my $name = shift;
    mark4delete($name, %crls);
}

##
 # get map of keys
 # @returns connection map
 #
BEGIN { $TYPEINFO{Keys} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub Keys()
{
    return \%keys;
}

##
 # delete a key
 # @param name
BEGIN { $TYPEINFO{deleteKey} = ["function", "void" , "string" ]; }
sub deleteKey($)
{
    my $name = shift;
    mark4delete($name, %keys);
}

##
 # adds file contents into current repositories
 # @param	file to import content from
 # @return	error message on error or undef
 #
BEGIN { $TYPEINFO{prepareImportFile} = ["function", "string", "string" ]; }
sub prepareImportFile($)
{
    my $file = shift;
    my $list = extract_ANY(file => $file, pwcb => \&passwordPrompt);

    unless(defined($list) and scalar(@{$list})) {
	return sprintf(_("nothing found in %s"), $file);
    }

    for my $dref (@{$list}) {
	debug "IMPORTING: ", $dref->{'info'}, $dref->{'name'} ?
	                     " (from '".$dref->{'name'}.")" : "";

	my $iref = parse_pem_data(info => $dref->{'info'},
	                          data => $dref->{'data'},
				  pwcb => \&passwordPrompt);
	if(defined($iref) and defined($iref->{'hash'})) {
	    my $pem;

	    # mark it imported / new
	    $iref->{'hash'}->{'NEW'}  = 1;
	    $iref->{'hash'}->{'info'} = $dref->{'info'};
	    $iref->{'hash'}->{'data'} = $dref->{'data'};

	    if($iref->{'type'} eq 'KEY') {
		unless(check_new_key(%{$iref->{'hash'}}, %keys)) {
		    $pem = get_free_idx("key_", ".pem", %keys);
		    $keys{$pem} = $iref->{'hash'};
		}
		next;
	    }

	    if($iref->{'type'} eq 'CRL') {
		my $pem = check_new_crl(%{$iref->{'hash'}}, %crls);
		if(defined($pem)) {
		    if($pem eq "") {
			$pem = get_free_idx("crl_", ".pem", %crls);
		    }
		    $crls{$pem} = $iref->{'hash'};
		}
		next;
	    }

	    if($iref->{'type'} eq 'CERT') {
		if($iref->{'hash'}->{"IS_CA"}) {
		    if(check_new_cert(%{$iref->{'hash'}},
		                      %cacertificates)) {
			$pem = get_free_idx("cacert_", ".pem",
			                    %cacertificates);
			$cacertificates{$pem} = $iref->{'hash'};
		    }
		} else {
		    if(check_new_cert(%{$iref->{'hash'}},
		                      %certificates)) {
			$pem = get_free_idx("cert_", ".pem",
		                            %certificates);
		        $certificates{$pem} = $iref->{'hash'};
		    }
		}
		next;
	    }
	}
    }
    return undef;
}

##
 # intergrates currents imports (removes new flags)
 # @return	undef or error string
 #
BEGIN { $TYPEINFO{finishImport} = ["function", "string" ]; }
sub finishImport()
{
    for my $file (keys %cacertificates) {
	my $_new = $cacertificates{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "finish cacertificates($file)";
	    $cacertificates{$file}->{'NEW'} = 2;
	}
    }

    for my $file (keys %certificates) {
	my $_new = $certificates{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "finish certificates($file)";
	    $certificates{$file}->{'NEW'} = 2;
	}
    }

    for my $file (keys %crls) {
    	my $_new = $crls{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "finish crls($file)";
	    $crls{$file}->{'NEW'} = 2;
	}
    }

    for my $file (keys %keys) {
	my $_new = $keys{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "finish keys($file)";
	    $keys{$file}->{'NEW'} = 2;
	}
    }
    return undef;
}

##
 # import cleanup method - deletes imported stuff
 #
BEGIN { $TYPEINFO{cleanupImport} = ["function", "void" ]; }
sub cleanupImport()
{
    for my $file (keys %cacertificates) {
	my $_new = $cacertificates{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "delete cacertificates($file)";
	    delete($cacertificates{$file});
	}
    }

    for my $file (keys %certificates) {
	my $_new = $certificates{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "delete certificates($file)";
	    delete($certificates{$file});
	}
    }

    for my $file (keys %crls) {
    	my $_new = $crls{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "delete crls($file)";
	    delete($crls{$file});
	}
    }

    for my $file (keys %keys) {
	my $_new = $keys{$file}->{'NEW'} || 0;
	if(1 == $_new) {
	    debug "delete keys($file)";
	    delete($keys{$file});
	}
    }
    return undef;
}

##
 # global cleanup method called on exit
 #
BEGIN { $TYPEINFO{cleanup} = ["function", "void" ]; }
sub cleanup()
{
    debug "starting cleanup";
    cleanupImport();
    debug "finished cleanup";
}

##
 # GUI callback function
 #  Parameter:	prompt string
 #  Returns:	password or undef for skip
 #
sub passwordPrompt($)
{
    return IPsecPopups::Password(shift);
}

##
 # import a ipsec.conf file
 # @param filename to load
 # @returns undef on success, error string otherwise
 #
BEGIN { $TYPEINFO{importConnection} = ["function", "string", "string" ]; }
sub importConnection($)
{
    my $file = shift;

    # TODO
    return "importing configs not yet implemented";
    
    return undef;
}

##
 # export a ipsec.conf file
 # @param name of connection
 # @param filename to store it. overwrite it if already exists
 # @returns undef on success, error string otherwise
 #
BEGIN { $TYPEINFO{exportConnection} = ["function", "string", "string", "string" ]; }
sub exportConnection($$)
{
    my $name = shift;
    my $file = shift;

    if(!exists($connections{$name}))
    {
       return sprintf(_("Connection \"%s\" does not exist"), $name);
    }

    # TODO
    return "importing configs not yet implemented";
    
    return undef;
}


######################################################################
##### CRAP, REMOVE ME IF UNUSED ######################################
######################################################################

##
 # import a CA certificate from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCACertificate} = ["function", "string", "string" ]; }
sub importCACertificate($)
{
#    my $filename = shift;
#    my $href = parse_cert(file => $filename);
#
#    if(!defined $href)
#    {
#	return _("importing CA certificate failed"); # FIXME
#    }
#
#    my $idx = 0;
#    while (exists $cacertificates{"cacert".$idx.".pem"})
#    {
#	$idx++;
#    }
#    $cacertificates{"cacert".$idx.".pem"} = $href;
#
#    return undef;
    debug "importCACertificate is obsolete!";
    return _("obsolete function - use prepareImportFile!");
}


##
 # import a CRL from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCRL} = ["function", "string", "string" ]; }
sub importCRL($)
{
#    my $filename = shift;
#    my $href = parse_crl(file => $filename);
#
#    if(!defined $href)
#    {
#	return _("importing CRL failed"); # FIXME
#    }
#
#    my $idx = 0;
#    while (exists $crls{"crl".$idx.".pem"})
#    {
#	$idx++;
#    }
#    $crls{"crl".$idx.".pem"} = $href;
#
#    return undef;
    debug "importCRL is obsolete!";
    return _("obsolete function - use prepareImportFile!");
}


##
 # import a certificate from file
 # @param filename to import
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importCertificate} = ["function", "string", "string" ]; }
sub importCertificate($)
{
#    my $filename = shift;
#    my $href = parse_cert(file => $filename);
#
#    return _("importing certificate failed") unless (defined $href);
#
#    my $saveas = get_free_key_for_hash("cert", ".pem", \%certificates);
#    return _("importing certificate failed") unless (defined $saveas);
#
#    FreeSwanCerts::save_certificate_as($filename, $saveas);
#    $certificates{$saveas} = $href;
#
#    return undef;
    debug "importCertificate is obsolete!";
    return _("obsolete function - use prepareImportFile!");
}

##
 # import a Key from file
 # @param filename to import
 # @param passwort (maybe empty, means no password)
 # @return error message on error or undef on success
BEGIN { $TYPEINFO{importKey} = ["function", "string", "string", "string" ]; }
sub importKey($)
{
#    my $filename = shift;
#    my $password = shift;
#    my $href = parse_key(file => $filename, pass => $password);
#
#    if(!defined $href)
#    {
#	return _("importing key failed"); # FIXME
#    }
#
#    my $idx = 0;
#    while (exists $keys{"key".$idx.".pem"})
#    {
#	$idx++;
#    }
#    $keys{"key".$idx.".pem"} = $href;
#
#    return undef;
    debug "importKEY is obsolete!";
    return _("obsolete function - use prepareImportFile!");
}

# EOF
# vim: sw=4
