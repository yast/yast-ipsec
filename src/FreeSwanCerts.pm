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
use Archive::Zip;
use File::Temp qw/ tempfile tempdir /;

require Exporter;

our @ISA         = qw (Exporter);
#
# FIXME: exports
#
our @EXPORT      = qw (list_CAs list_CERTs list_KEYs list_files
                       parse_cert parse_crl parse_key parse_pem_data
                      );
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

our $ZIP_MAX_SIZE = 100 * 1024; # 100 kbyte per file in zip
our $rx_cert_der  = qr /(?:der|cer)/io;
our $rx_cert_pem  = qr /(?:pem|crt|crl)/io;
our $rx_cert_ext  = qr /(?:pem|crt|crl|der|cer)/io;
our $rx_pk12_ext  = qr /(?:pkcs12|p12|pfx)/io;


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


# --------------------------------------------------------------------
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


# --------------------------------------------------------------------
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

# --------------------------------------------------------------------
sub list_KEYs($;$)
{
    my $openssl = shift;
    my $dir     = shift || $DEFS{'ipsec_private'};
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

# --------------------------------------------------------------------
sub list_files($;$)
{
    my $dir = shift;
    my $ext = shift;
    my @certs;

    unless(defined($ext) and length("".$ext)) {
        $ext = qr /^.+\.${rx_cert_ext}$/o;
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


# --------------------------------------------------------------------
sub parse_cert($$)
{
    my $openssl = shift;
    my $infile  = shift;
    my $inform  = 'PEM';

    unless(defined($infile) and $infile =~ /\S+/) {
        $infile = '' unless(defined($infile));
        print STDERR "ERROR: invalid file name '$infile'\n"
            if($DEBUG);
        return undef;
    }
    $inform = 'DER' if($infile =~ /\.${rx_cert_der}$/);

    my $X509 = new OpenCA::X509(INFILE=>$infile,
                                INFORM=>$inform,
                                SHELL =>$openssl);
    unless($X509) {
        print STDERR "ERROR: unable to parse cert '$infile': $!\n"
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

            print STDERR "SubjectAltName($infile): $subjaltname\n"
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

# --------------------------------------------------------------------
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


# --------------------------------------------------------------------
sub parse_key($$)
{
    return undef;
}

sub is_certificate($)
{
# if /------BEGIN CERTIF/ ...
	return 1;
}


# --------------------------------------------------------------------
sub parse_pem_data($)
{
    my $blub = shift;
    return undef unless(defined($blub) and length($blub));

    my @list = ();
    my $type = undef;
    my $data = undef;
    for my $line (split(/\n/, $blub)) {
        if(defined($type)) {
            if($line =~ /^[-]{5}END[ ]([A-Z0-9 ]+)+[-]{5}$/) {
                if($type eq $1) {
                    push(@list, {
                            type => $type,
                            data => $data,
                        });
                }
                $type = undef;
                $data = undef;
            } else {
                $data .= $line;
            }
        } else {
            if($line =~ /^[-]{5}BEGIN[ ]([A-Z0-9 ]+)+[-]{5}$/) {
                $type = "$1";
                $data = $line;
            }
        }
    }

    return \@list;
}


# --------------------------------------------------------------------
sub extract_P12
{
    my $openssl  = shift;
    my $file     = shift;
    my $pass     = shift;

    return undef unless(defined($file) and length($file) and -f $file);
    my $blub = $openssl->dataConvert(
        DATATYPE  =>'CERTIFICATE',
        P12PASSWD => $pass,
        INFORM    => "PKCS12",
        INFILE    => $file,
        OUTFORM   => "PEM",
    );
    return parse_pem($blub);
}

# --------------------------------------------------------------------
sub extract_ZIP
{
    my $file = shift;
    return undef unless(defined($file) and length($file) and -f $file);

    my @list = ();
    my $zip = Archive::Zip->new($file);
    for my $member ($zip->members()) {
        next unless(defined($member->fileName()));
        next if($member->uncompressedSize() > $ZIP_MAX_SIZE);

        if($member->fileName() =~ /\.${rx_cert_pem}$/) {
            my $lref = parse_pem_data($member->contents());
            if(defined($lref)) {
                push(@list, @{$lref});
            }
            next;
        }
        if($member->fileName() =~ /\.${rx_pk12_ext}$/) {
            my ($fh, $fn) = tempfile("pkcs12XXXXXX",
                                     "SUFFIX" => ".p12");
            if($fh and $fn) {
                if("AZ_OK" eq $member->extractToFileHandle($fh)) {
                    my $lref = extract_P12($fn);
                    if(defined($lref)) {
                        push(@list, @{$lref});
                    }
                }
                unlink($fn);
            }
            next;
        }
    }
    return scalar(@list) ? \@list : undef;
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
