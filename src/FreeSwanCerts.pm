# -*- perl -*-
#
# File:         modules/FreeSwanCerts.pm
# Package:      YaST2 IPSec configuration
# Summary:      FreeS/WAN certificate utilities
# Authors:      Ludwig Nussel <lnussel@suse.de>,
#               Marius Tomaschewski <mt@suse.de>
#
# $Id$
#
package FreeSwanCerts;
use 5.008000;
use strict;
use warnings;
use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;

require Exporter;

our @ISA         = qw (Exporter);
#
# FIXME: exports
#
our @EXPORT      = qw(list_CAs list_CERTs list_KEYs list_files);
our %EXPORT_TAGS = (
        'all' => [ @EXPORT ]
    );
our @EXPORT_OK   = ( @{ $EXPORT_TAGS{'all'} } );

our $VERSION     = 0.1;
our $DEBUG       = 5;  # level 0 .. 4

# FIXME:
our %DEFS        = (
    'ipsec_version'  => '2.0',
    'ipsec_root'     => '',
    'ipsec_conf'     => '/etc/ipsec.conf',
    'ipsec_secrets'  => '/etc/ipsec.secrets',
    'ipsec_dir'      => '/etc/ipsec.d',
    'ipsec_policies' => '/etc/ipsec.d/policies',
    'ipsec_crls'     => '/etc/ipsec.d/crls',
    'ipsec_certs'    => '/etc/ipsec.d/certs',
    'ipsec_cacerts'  => '/etc/ipsec.d/cacerts',
    'ipsec_private'  => '/etc/ipsec.d/private',
);


#
# === public functions ===============================================
#
sub list_CAs($;$)
{
    my $openssl = shift;
    my $dir  = shift || $DEFS{'ipsec_cacerts'};
    my %certs;

    foreach my $file (list_files($dir)) {
        my $cert = parse_cert($openssl, $file);
        if(defined($cert)) {
            $certs{$file} = $cert;
        }
    }
    return %certs;
}


#
# --------------------------------------------------------------------
#
sub list_CRLs($;$)
{
    my $openssl = shift;
    my $dir  = shift || $DEFS{'ipsec_crls'};
    my %certs;

    foreach my $file (list_files($dir)) {
        my $cert = parse_crl($openssl, $file);
        if(defined($cert)) {
            $certs{$file} = $cert;
        }
    }
    return %certs;
}


#
# --------------------------------------------------------------------
#
sub list_CERTs($;$)
{
    my $openssl = shift;
    my $dir  = shift || $DEFS{'ipsec_certs'};
    my %certs;

    foreach my $file (list_files($dir)) {
        my $cert = parse_cert($openssl, $file);
        if(defined($cert)) {
            $certs{$file} = $cert;
        }
    }
    return %certs;
}

#
# --------------------------------------------------------------------
#
sub list_KEYs($;$)
{
    my $openssl = shift;
    my $dir  = shift || $DEFS{'ipsec_private'};
    my %certs;

# FIXME: need passwd for...
#    foreach my $file (list_files($dir)) {
#        my $cert = parse_key($openssl, $file);
#        if(defined($cert)) {
#            $certs{$file} = $cert;
#        }
#    }
    return %certs;
}


#
# === private helpers ================================================
#
sub list_files($;$)
{
    my $dir = shift;
    my $ext = shift;
    my @certs;

    unless(defined($ext) and length("".$ext)) {
        $ext = qr/^.+\.(?:pem|der|cer|asc)$/;
    }
    if($dir and -d $dir and opendir(DIR, $dir)) {
        $dir =~ s/\/\//\//g;
        $dir =~ s/\/\.\//\//g;
        $dir =~ s/\/$//;
        @certs = map { 
            $dir.'/'.$_
        } grep {
            !/^\.\.?$/ and /$ext/
        } readdir(DIR);
    }
    return @certs;
}

#
# --------------------------------------------------------------------
#
sub parse_cert($$)
{
    my $openssl = shift;
    my $file    = shift;

    my $X509 = new OpenCA::X509(INFILE=>$file , SHELL=>$openssl);
    unless($X509) {
        print STDERR "ERROR: unable to parse cert '$file': $!\n"
            if($DEBUG);
        return undef;
    }

    my $parsed = $X509->getParsed();
    my $subjaltname = undef;

    if(exists($parsed->{"OPENSSL_EXTENSIONS"}) and
       ref($parsed->{"OPENSSL_EXTENSIONS"}) eq 'HASH') {
        my $ref = $parsed->{"OPENSSL_EXTENSIONS"};

        if(exists($ref->{"X509v3 Subject Alternative Name"}) and
           scalar(@{$ref->{"X509v3 Subject Alternative Name"}||[]})) {

            # just use the first one
            $subjaltname = $ref->{"X509v3 Subject Alternative Name"}[0];

            print STDERR "SubjectAltName($file): $subjaltname\n"
                if($DEBUG);

            # FIXME: do we need to add @ for DNS?
            $subjaltname =~ s/^(?:email|ip|dns)://i;
        }
    }

    my %cert;
    $cert{"DN"}            = $parsed->{"DN"};
    $cert{"ISSUER"}        = $parsed->{"ISSUER"};
    $cert{"subjectAltName"}= $subjaltname;
    return \%cert;
}

#
# --------------------------------------------------------------------
#
sub parse_crl($$)
{
    my $openssl = shift;
    my $file = shift;

    my $CRL = new OpenCA::CRL(INFILE=>$file , SHELL=>$openssl);
    unless($CRL) {
        print STDERR "ERROR: unable to parse crl '$file': $!\n"
            if($DEBUG);
        return undef;
    }

    my $parsed = $CRL->getParsed();
    my $subjaltname;

    if(exists($parsed->{"OPENSSL_EXTENSIONS"}) and
       ref($parsed->{"OPENSSL_EXTENSIONS"}) eq "HASH") {
        my $ref = $parsed->{"OPENSSL_EXTENSIONS"};

        if(exists($ref->{"X509v3 Subject Alternative Name"}) and
           scalar(@{$ref->{"X509v3 Subject Alternative Name"}||[]})) {

            # just use the first one
            $subjaltname = $ref->{"X509v3 Subject Alternative Name"}[0];

            print STDERR "SubjectAltName($file): $subjaltname\n"
                if($DEBUG);

            # FIXME: do we need to add @ for DNS?
            $subjaltname =~ s/^(?:email|ip|dns)://i;
        }
    }

    my %cert;
    $cert{"ISSUER"}     = $parsed->{"ISSUER"};
    $cert{"NEXT_UPDATE"}= $parsed->{"NEXT_UPDATE"};
    $cert{"LAST_UPDATE"}= $parsed->{"LAST_UPDATE"};
    return \%cert;
}

1;
__END__

=head1 NAME

FreeSwanCerts - FreeS/WAN certificate utilities

=head1 DESCRIPTION

FreeSwanCerts implements functions to manage certificates.

=head1 SYNOPSIS

    use FreeSwanCerts;

=head1 FUNCTIONS

=over 4

=item B<load_certs( )>

=back

=head1 SEE ALSO

L<ipsec.conf(5)>
L<ipsec.secrets(5)>

=head1 AUTHORS

=over 4

=item Ludwig Nussel E<lt>lnussel@suse.deE<gt>

=item Marius Tomaschewski, E<lt>mt@suse.deE<gt>

=back

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by SUSE LINUX AG, Nuernberg, Germany

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
#
# vim: set ts=8 sts=4 sw=4 ai et:
#
