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

YaST::YCP::Import ("SCR");

setlocale(LC_MESSAGES, "");
textdomain("ipsec");

my %connections;
my %settings;

sub _ {
    return gettext($_[0]);
}

our %TYPEINFO;

BEGIN
{
    print STDERR "constructor\n";
}

##
 # Read all ipsec settings
 # @return true on success
 #
BEGIN { $TYPEINFO{Read} = ["function", "boolean"]; }
sub Read
{
    my $ref = SCR::Read('.etc.ipsec.conf');

    return Boolean(0) if(ref($ref) ne 'HASH');

    %settings = %{$ref->{"config setup"}};

    delete $ref->{"config setup"};

    %connections = %{$ref};

    return Boolean(1);
}

BEGIN { $TYPEINFO{Connections} = ["function", [ "map", "string", [ "map", "string", "string" ]]]; }
sub Connections()
{
    return \%connections;
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
