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
#    open(STDERR, ">", "/dev/null") unless($DEBUG);
#    $SIG{'PIPE'} = 'IGNORE';
}

use strict;
use warnings;
use diagnostics;
# Tranlator: do _not_ translate this! The reason why it's in the pot file is a
# technical deficiency
use Locale::gettext ("!textdomain");
use POSIX;  # Needed for setlocale()
use File::Temp qw(tempdir);
use File::Path;

use lib "/usr/share/YaST2/modules"; #### FIXME!!!
use FreeSwanUtils;
use FreeSwanCerts;
use Date::Calc qw (Parse_Date Date_to_Time);

use YaST::YCP qw(:LOGGING Boolean);
YaST::YCP::Import ("IPsecPopups");
YaST::YCP::Import ("Popup");

POSIX::setlocale(LC_MESSAGES, "");
my $TXTDOMAIN = "ipsec";
$FreeSwanUtils::TXTDOMAIN = $TXTDOMAIN;

my $fsutil;
my %connections;
my %settings;

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

our %TYPEINFO;

BEGIN
{
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
    %settings = ();
    %connections = ();

    if($fsutil->load_config()) {
	%settings = %{$fsutil->settings()};

	my @conns = $fsutil->conns(exclude => [qw(%default %implicit)]);
	for my $name (@conns) {
	    debug "copy connections += $name";
	    $connections{$name} = {$fsutil->conn($name)};
	}
    } else {
	debug $fsutil->errstr();
	return Boolean(0);
    }

    unless($fsutil->load_secrets()) {
	debug $fsutil->errstr();
	return Boolean(0);
    }

    # parse all CAs
    for my $file (FreeSwanCerts::list_CAs()) {
	my $cert = parse_cert(file => $file);
	next unless(defined($cert));
	$cacertificates{$file} = $cert;
    }

    # parse all CRLs
    for my $file (FreeSwanCerts::list_CRLs()) {
	my $crl = parse_crl(file => $file);
	next unless(defined($crl));
	$crls{$file} = $crl;
    }

    # parse all Certs
    for my $file (FreeSwanCerts::list_CERTs()) {
	my $cert = parse_cert(file => $file);
	next unless(defined($cert));
	$certificates{$file} = $cert;
    }

    # get all x509 keys from ipsec.secres
    for my $kref ($fsutil->secrets(type => 'RSA')) {
	next unless(defined($kref->{'x509'}));
	$keys{$kref->{'x509'}} = {'PASSWORD' => $kref->{'pass'}};
    }

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
    # Delete scheduled files
    #
    for my $file (keys %deleted) {
	if(length($file) and -f $file) {
	    debug "deleting file $file";
	    unlink($file);
	}
    }

    #
    # Save FreeS/WAN setup
    #
    for my $name (keys %settings) {
	debug "apply setting '$name' => ". $settings{$name} . "\n";
    }
    $fsutil->settings(%settings);

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
    if($fsutil and not($fsutil->save_config())) {
	# Translator: error message concatenated after colon
	Popup::Error("IPsecConfig", dgettext($TXTDOMAIN,
	             "Failed to save ipsec.conf:")."\n"
	             . $fsutil->errstr());
	return Boolean(0);
    }

    #
    # Save FreeS/WAN secrets
    #
    for my $kref ($fsutil->secrets(type => 'RSA')) {
	next unless(defined($kref->{'x509'}));
	unless(exists($keys{$kref->{'x509'}})) {
            debug "deleting x509-key '", $kref->{'x509'}, "' from secrets";
	    $fsutil->secret_del(type => 'RSA', x509 => $kref->{'x509'});
	} else {
            debug "keeping x509-key '", $kref->{'x509'}, "' in secrets";
        }
    }
    for my $file (keys %keys) {
	my $pass = $keys{$file}->{'PASSWORD'};
	$fsutil->secret_set(type => 'RSA',
	                    x509 => $file,
	                    pass => $pass);
        debug "updateing 509-key '$file' in secrets";
    }
    if($fsutil and not($fsutil->save_secrets())) {
	# Translator: error message concatenated after colon
	Popup::Error("IPsecConfig", dgettext($TXTDOMAIN,
	             "Failed to save ipsec.secrets:")."\n"
	             . $fsutil->errstr());
	return Boolean(0);
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
	    Popup::Error("IPsecConfig",
			# Translator: filename, error message
	                 sprintf(dgettext($TXTDOMAIN,
	                         "Cannot write file %s: %s"),
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
	    Popup::Error("IPsecConfig",
			# Translator: filename, error message
	                 sprintf(dgettext($TXTDOMAIN,
	                         "Cannot write file %s: %s"),
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
	    Popup::Error("IPsecConfig",
			# Translator: filename, error message
	                 sprintf(dgettext($TXTDOMAIN,
	                         "Cannot write file %s: %s"),
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
	    Popup::Error("IPsecConfig",
			# Translator: filename, error message
	                 sprintf(dgettext($TXTDOMAIN,
	                         "Cannot write file %s: %s"),
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
    # FIXME:
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
    my $pkg = shift; # FIXME
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
    my $pkg = shift; # FIXME
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
    my $pkg = shift; # FIXME
    my $name = shift;

    my $err = $fsutil->is_valid_conn_name($name);
    if($err) {
	return sprintf(dgettext($TXTDOMAIN,
	               "Connection name '%s' is a reserved or implicit name."),
                       $name) if(2 == $err);
	return dgettext($TXTDOMAIN,
	       "A connection name can contain only a-z, 0-9, _, and - characters.");
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
    my $pkg = shift; # FIXME
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
	"left" => "\%defaultroute",
	"leftrsasigkey" => "\%cert",
	"rightrsasigkey" => "\%cert",
	"keyingtries" => "3",
	"auto" => "ignore",
	"esp" => "aes,3des",
	"pfs" => "yes",
	"authby" => "rsasig",
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

    $conn->{"left"} = "\%defaultroute";
    $conn->{"right"} = "\%any";
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

    $conn->{"left"} = "\%defaultroute";
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
    else
    {
	y2error("$name does not exist in hash");
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

    return undef unless(defined($cert->{'DN'}) and $cert->{'DN'} ne "");
    for my $idx (keys %{$href}) {
	if($cert->{'DN'} eq $href->{$idx}->{'DN'}) {
	    debug "cert dn already exists: ", $cert->{'DN'} || '';
	    return $idx;
	}
    }
    debug "cert dn is new: ", $cert->{'DN'} || '';
    return "";
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
    return "";
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
    my $pkg = shift; # FIXME
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
    my $pkg = shift; # FIXME
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
    my $pkg = shift; # FIXME
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
    my $pkg = shift; # FIXME
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
    my $pkg = shift; # FIXME
    my $file = shift;
    my $list = extract_ANY(file => $file, pwcb => \&passwordPrompt);

    unless(defined($list) and scalar(@{$list})) {
	# Translator: %s = filename
	return sprintf(dgettext($TXTDOMAIN,"Nothing found in %s."), $file);
    }

    for my $dref (@{$list}) {
	debug "IMPORTING: ", $dref->{'info'}, $dref->{'name'} ?
	                     " (from '".$dref->{'name'}.")" : "";

	my $iref = parse_pem_data(info => $dref->{'info'},
	                          data => $dref->{'data'},
				  pwcb => \&passwordPrompt);
	if(defined($iref) and defined($iref->{'hash'})) {
            my ($pem, $dir);

	    # mark it imported / new
	    $iref->{'hash'}->{'NEW'}  = 1;
	    $iref->{'hash'}->{'info'} = $dref->{'info'};
	    $iref->{'hash'}->{'data'} = $dref->{'data'};

	    if($iref->{'type'} eq 'KEY') {
		$pem = check_new_key(%{$iref->{'hash'}}, %keys);
		if(defined($pem) and $pem eq "") {
		    $dir = $FreeSwanCerts::DEFS{'ipsec_private'};
		    $pem = get_free_idx($dir."/key_", ".pem", %keys);
		    $keys{$pem} = $iref->{'hash'};
		}
		next;
	    }

	    if($iref->{'type'} eq 'CRL') {
		$pem = check_new_crl(%{$iref->{'hash'}}, %crls);
		if(defined($pem)) {
		    # add or update
		    if($pem eq "") {
			$dir = $FreeSwanCerts::DEFS{'ipsec_crls'};
			$pem = get_free_idx($dir."/crl_", ".pem", %crls);
		    } else {
			mark4delete($pem, %crls);
		    }
		    $crls{$pem} = $iref->{'hash'};
		}
		next;
	    }

	    if($iref->{'type'} eq 'CERT') {
		if($iref->{'hash'}->{"IS_CA"}) {
		    $pem = check_new_cert(%{$iref->{'hash'}},
		                          %cacertificates);
		    if(defined($pem) and $pem eq "") {
			$dir = $FreeSwanCerts::DEFS{'ipsec_cacerts'};
			$pem = get_free_idx($dir."/cacert_", ".pem",
			                    %cacertificates);
			$cacertificates{$pem} = $iref->{'hash'};
		    }
		} else {
		    $pem = check_new_cert(%{$iref->{'hash'}},
					  %certificates);
		    if(defined($pem) and $pem eq "") {
			$dir = $FreeSwanCerts::DEFS{'ipsec_certs'};
			$pem = get_free_idx($dir."/cert_", ".pem",
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
    my $headline = shift;
    return IPsecPopups::Password("fsdf", $headline); # FIXME
}

##
 # import a ipsec.conf file
 # @param filename to load
 # @returns undef on success, error string otherwise
 #
BEGIN { $TYPEINFO{importConnection} = ["function", "string", "string" ]; }
sub importConnection($)
{
    my $pkg = shift; # FIXME
    my $file = shift;

    # TODO
    return "importing configs not yet implemented";
    
    return undef;
}

##
 # export a ipsec.conf file
 # @param name of connection
 # @param filename to store it. overwrite it if already exists
 # @param boolean whether to use freeswan format. false if windows
 # @returns undef on success, error string otherwise
 #
BEGIN { $TYPEINFO{exportConnection} = ["function", "string", "string", "string", "boolean" ]; }
sub exportConnection($$)
{
    my $pkg = shift; # FIXME
    my $name = shift;
    my $file = shift;
    my $freeswan = shift;

    if(!exists($connections{$name}))
    {
       return sprintf(dgettext($TXTDOMAIN,
                      "Connection \"%s\" does not exist."), $name);
    }

    my $conn = $connections{$name};

    unlink($file);

    sysopen(HANDLE, $file, O_RDWR|O_CREAT|O_EXCL) or return "sysopen $file: $!";

    my $host = `/bin/hostname -f` || 'server';
    $host =~ s/\n$//;
    my $conname = $host;
    $conname =~ s/[^a-zA-Z]/_/g;

    my $crlcheckinterval = $settings{"crlcheckinterval"} || "0";
    my $strictcrlpolicy = $settings{"strictcrlpolicy"} || "no";
    my $nat_traversal = $settings{"nat_traversal"} || "no";

    my $esp = $conn->{'esp'};
    my $keyingtries = $conn->{'keyingtries'};
    my $pfs = $conn->{'pfs'};
    my $right = $conn->{'left'};
    my $rightid = $conn->{'leftid'};
    my $leftid = $conn->{'rightid'};
    my $leftsubnet = $conn->{'rightsubnet'};
    my $rightsubnet = $conn->{'leftsubnet'};

    $right = $host if($right =~ /^%/) ;

    if($freeswan)
    {
	print HANDLE (
	"# configuration file for Linux FreeS/WAN Version 2\n",
	"# modify for your needs and save it as /etc/ipsec.conf\n",
	"#\n",
	"# Note: To extract the private key from your client\n",
	"# certificate in p12 format into a pem file, use:\n",
	"#\n",
	"#   openssl pkcs12 -nocerts -nodes -in FILE.p12 \\\n",
	"#           -out /etc/ipsec.d/private/key_01.pem\n",
	"#\n",
	"# To extract the client certificate, use:\n",
	"#\n",
	"#   openssl pkcs12 -clcerts -nokeys -in FILE.p12 \\\n",
	"#           -out /etc/ipsec.d/certs/cert_01.pem\n",
	"#\n",
	"# To extract the CA certificate, use:\n",
	"#\n",
	"#   openssl pkcs12 -cacerts -nokeys -in FILE.p12 \\\n",
	"#           -out /etc/ipsec.d/cacerts/cacert_01.pem\n",
	"#\n",
	"# Do not forget to add (replace) a key reference\n",
	"# line in the /etc/ipsec.secrets file, e.g.:\n",
	"#   : RSA /etc/ipsec.d/private/key_01.pem \"\"\n",
	"#\n",
	"# and to apply proper permissions to both files:\n",
	"#\n",
	"#   chmod 0600  /etc/ipsec.secrets \\\n",
	"#               /etc/ipsec.d/private/key_01.pem\n",
	"#   chown root: /etc/ipsec.secrets \\\n",
	"#               /etc/ipsec.d/private/key_01.pem\n",
	"#\n",
	"#\n",
	"version 2.0\n",
	"\n",
	"# basic configuration\n",
	"config setup\n",
	"	crlcheckinterval=\"$crlcheckinterval\"\n",
	"	strictcrlpolicy=\"$strictcrlpolicy\"\n",
	"	nat_traversal=\"$nat_traversal\"\n",
	"\n",
	"conn \%default\n",
	"	leftrsasigkey=\%cert\n",
	"	rightrsasigkey=\%cert\n",
	"\n",
	"# OE policy groups are disabled by default\n",
	"conn block\n",
	"	auto=ignore\n",
	"\n",
	"conn clear\n",
	"	auto=ignore\n",
	"\n",
	"conn private\n",
	"	auto=ignore\n",
	"\n",
	"conn private-or-clear\n",
	"	auto=ignore\n",
	"\n",
	"conn clear-or-private\n",
	"	auto=ignore\n",
	"\n",
	"conn packetdefault\n",
	"	auto=ignore\n",
	"\n",
	);

	print HANDLE "conn me_to_$conname\n";
	print HANDLE "\tauto=\"start\"\n";
	print HANDLE "\tauthby=\"rsasig\"\n";
	print HANDLE "\tesp=\"$esp\"\n" if $esp;
	print HANDLE "\tkeyingtries=\"$keyingtries\"\n" if $keyingtries;
	print HANDLE "\tpfs=\"$pfs\"\n" if $pfs;
	print HANDLE "\tleft=\"\%defaultroute\"\n";
	print HANDLE "\tleftid=\"$leftid\"\n" if ($leftid && $leftid ne '%any');
	print HANDLE "\t# change this to the actual name of your certificate\n";
	print HANDLE "\tleftcert=\"/etc/ipsec.d/certs/cert_01.pem\"\n";
	print HANDLE "\tleftrsasigkey=\"\%cert\"\n";
	print HANDLE "\tleftsubnet=\"$leftsubnet\"\n" if $leftsubnet;
	print HANDLE "\tright=\"$right\"\n";
	print HANDLE "\trightid=\"$rightid\"\n";
	print HANDLE "\trightrsasigkey=\"\%cert\"\n";
	print HANDLE "\trightsubnet=\"$rightsubnet\"\n" if $rightsubnet;
    }
    else
    {
	my $leftcert = $conn->{"leftcert"};
	my $issuer = $certificates{$leftcert}->{"ISSUER_FORWINDOWSEXPORT"} || 'CN=CA, ...';

	print HANDLE (
	"#\r\n",
	"# ipsec.conf - IPSec configuration file sample.\r\n",
	"#\r\n",
	"### WinXP/2k ###############################\r\n",
	"#\r\n",
	"# ==>> Configuration for WinXP and Win2K  <<==\r\n",
	"#\r\n",
	"#   See also: http://vpn.ebootis.de/\r\n",
	"#\r\n",
	"conn me_to_$conname\r\n",
	"	pfs=$pfs\r\n",
	"	auto=start\r\n",
	"	network=auto\r\n",
	"	#\r\n",
	"	# Local side:\r\n",
	"	left=\%any\r\n",
	"	#\r\n",
	"	# Remote side:\r\n",
	"	#   $host Hostname/IP:\r\n",
	"	right=$right\r\n",
	"	# $host CA Issuer DN:\r\n",
	"	rightca=\"$issuer\"\r\n",
	);
	
	print HANDLE "\trightsubnet=$rightsubnet\r\n" if $rightsubnet;
    }

    close HANDLE;

    return undef;
}

__END__
Help YaST2 distutils a little bit:
    Textdomain "ipsec"

# EOF
# vim: sw=4
