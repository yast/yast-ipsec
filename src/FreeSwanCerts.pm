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
use OPENSSL;
use Archive::Zip;
use Fcntl;
use File::Temp qw/ tempfile tempdir /;
use Locale::gettext;
require Exporter;

our @ISA         = qw (Exporter);
#
# FIXME: exports
#
our @EXPORT      = qw (list_CAs list_CERTs list_KEYs list_files
                       extract_ANY write_pem_data parse_pem_data
                       parse_cert parse_crl parse_key parse_pem_data);

our $VERSION     = 0.1;
our $DEBUG       = 0;  # level 0 .. 4

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
our $rx_pk12_ext  = qr /(?:p12|pk12|pfx)/io;


#
# === public functions ===============================================
#
sub list_CAs(;$)
{
    my $dir  = shift || $DEFS{'ipsec_cacerts'};
    # FIXME: ext
    return list_files($dir);
}


# --------------------------------------------------------------------
sub list_CRLs(;$)
{
    my $dir  = shift || $DEFS{'ipsec_crls'};
    # FIXME: ext
    return list_files($dir);
}


# --------------------------------------------------------------------
sub list_CERTs(;$)
{
    my $dir  = shift || $DEFS{'ipsec_certs'};
    # FIXME: ext
    return list_files($dir);
}


# --------------------------------------------------------------------
sub list_KEYs(;$)
{
    my $dir     = shift || $DEFS{'ipsec_private'};
    # FIXME: ext
    return list_files($dir);
}


# --------------------------------------------------------------------
sub list_files($;$)
{
    my $dir = shift;
    my $ext = shift;
    my @certs;

    # FIXME: ext ??
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
# {file => name, data => ...}
sub parse_cert(%)
{
    my %args    = @_;
    my $inform  = 'PEM';
    my $indata  = $args{'data'};
    my $infile  = undef;

    unless(defined($indata) and length($indata)) {
        $infile = $args{'file'};
        unless(defined($infile) and $infile =~ /\S+/) {
            $infile = '' unless(defined($infile));
            print STDERR "ERROR: invalid file name '$infile'\n"
                if($DEBUG);
            return undef;
        }
        $inform = 'DER' if($infile =~ /\.${rx_cert_der}$/);
    }

    my $ossl = new OPENSSL();
    my $parsed = $ossl->getParsedCert(DATA  =>$indata,
                                      INFILE=>$infile,
                                      INFORM=>$inform);
    unless($parsed) {
        print STDERR "ERROR: $OPENSSL::errmsg\n" if($DEBUG);
        return undef;
    }
    my $subjaltname = undef;

    if(exists($parsed->{"OPENSSL_EXTENSIONS"}) and
       ref($parsed->{"OPENSSL_EXTENSIONS"}) eq 'HASH') {
        my $ref = $parsed->{"OPENSSL_EXTENSIONS"};

        if(exists($ref->{"X509v3 Subject Alternative Name"}) and
           scalar(@{$ref->{"X509v3 Subject Alternative Name"}||[]})) {

            # just use the first one
            $subjaltname = $ref->{"X509v3 Subject Alternative Name"}[0];

            print STDERR "SubjectAltName(", $infile||'',
                         "): $subjaltname\n" if($DEBUG);

            # FIXME: do we need to add @ for DNS?
            $subjaltname =~ s/^(?:email|ip|dns)://i;
        }
    }

    print STDERR "IS_CA(",$infile||'',") => ",
                 $parsed->{"IS_CA"}, "\n" if($DEBUG);

    my %cert;
    $cert{"IS_CA"}         = $parsed->{"IS_CA"};
    $cert{"DN"}            = $parsed->{"DN"};
    $cert{"ISSUER"}        = $parsed->{"ISSUER"};
    $cert{"subjectAltName"}= $subjaltname;
    return \%cert;
}

# --------------------------------------------------------------------
# {file => name, data => ...}
sub parse_crl(%)
{
    my %args    = @_;
    my $inform  = 'PEM';
    my $indata  = $args{'data'};
    my $infile  = undef;

    unless(defined($indata) and length($indata)) {
        $infile = $args{'file'};
        unless(defined($infile) and $infile =~ /\S+/) {
            $infile = '' unless(defined($infile));
            print STDERR "ERROR: invalid file name '$infile'\n"
                if($DEBUG);
            return undef;
        }
        $inform = 'DER' if($infile =~ /\.${rx_cert_der}$/);
    }
    print STDERR "parse_crl($infile, $inform)\n" if($DEBUG);

    my $ossl = new OPENSSL();
    my $parsed = $ossl->getParsedCRL(DATA  =>$indata,
                                     INFILE=>$infile,
                                     INFORM=>$inform);
    unless($parsed) {
        print STDERR "ERROR: $OPENSSL::errmsg\n" if($DEBUG);
        return undef;
    }
    my %cert;
    $cert{"ISSUER"}     = $parsed->{"ISSUER"};
    $cert{"NEXT_UPDATE"}= $parsed->{"NEXTUPDATE"};
    $cert{"LAST_UPDATE"}= $parsed->{"LASTUPDATE"};
    return \%cert;
}


# --------------------------------------------------------------------
# {file => name, data => ..., pass => ...}
sub parse_key(%)
{
    my %args    = @_;
    my $inform  = 'PEM';
    my $indata  = $args{'data'};
    my $infile  = undef;
    my $passwd  = $args{'pass'};

    unless(defined($indata) and length($indata)) {
        $infile = $args{'file'};
        unless(defined($infile) and $infile =~ /\S+/) {
            $infile = '' unless(defined($infile));
            print STDERR "ERROR: invalid file name '$infile'\n"
                if($DEBUG);
            return undef;
        }
        $inform = 'DER' if($infile =~ /\.${rx_cert_der}$/);
    }
    my $ossl = new OPENSSL();
    my $blub = undef;
    if($ossl) {
       $blub = $ossl->convert(
            DATATYPE  => 'KEY',
            INPASSWD  => $passwd,
            INFORM    => $inform,
            INFILE    => $infile,
            DATA      => $indata,
            OUTFORM   => "TXT"
        );
    }
    unless($blub) {
        print STDERR "ERROR: $OPENSSL::errmsg\n" if($DEBUG);
        return undef;
    }
    my %hash;

    if($blub =~ /Private-Key: \((\d+) bit\)/) {
        $hash{"BITS"} = $1;
    }
    $hash{"FORMAT"}   = $inform;
    $hash{"PASSWORD"} = $passwd;
    return \%hash;
}

# --------------------------------------------------------------------
sub parse_pem_data(%)
{
    my %args    = @_;
    my $data    = $args{'data'};
    my $info    = $args{'info'};
    my $pwcb    = $args{'pwcb'}; # need it for key...

    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    my $type    = pem_type_by_string($info);
    if(defined($type)) {
        my $href = undef;
        if('KEY'  eq $type) {
            my $pass = undef;
            do {
                if(defined($pass)) {
                    $pass = &$pwcb(_("Wrong password.")."\n".
                                   _("RSA key password"));
                } else {
                    $pass = &$pwcb(_("RSA key password"));
                }
                return undef unless(defined($pass));
                $href = parse_key(data => $data, pass => $pass);
            } while(not defined($href));
        }
        if('CRL'  eq $type) {
            $href = parse_crl (data => $data);
        }
        if('CERT' eq $type) {
            $href = parse_cert(data => $data)
        }
        return { type => $type, hash => $href };
    }
    return undef;
}


# --------------------------------------------------------------------
sub pem_type_by_string($)
{
    my $string = shift;
    if(defined($string)) {
        return 'KEY'  if($string =~ /PRIVATE KEY$/);
        return 'CRL'  if($string =~ /CRL$/);
        return 'CERT' if($string =~ /CERTIFICATE$/);
    }
    return undef;
}


# --------------------------------------------------------------------
sub write_pem_data($$$)
{
    my $file = shift;
    my $data = shift;
    my $perm = shift;

    if($file and $data and $perm) {
        if(sysopen(OUT, $file, O_WRONLY|O_CREAT|O_EXCL, $perm)) {
            print OUT $data;
            close(OUT);
            return undef;
        }
        return "$!";
    }
    return _("invalid arguments");
}


# --------------------------------------------------------------------
sub extract_ANY(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};

    print STDERR "extract_ANY($file, $pwcb)\n" if($DEBUG);
    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    if(defined($file) and length($file) and -f $file) {
        if($file =~ /^.+\.zip$/io) {
            return extract_ZIP(file => $file, pwcb => $pwcb);
        }
        if($file =~ /^.+\.${rx_pk12_ext}$/) {
            return extract_P12(file => $file, pwcb => $pwcb);
        }
        if($file =~ /^.+\.${rx_cert_der}$/) {
            return extract_DER(file => $file, pwcb => $pwcb);
        }
        if($file =~ /^.+\.${rx_cert_pem}$/) {
            return extract_PEM(file => $file, pwcb => $pwcb);
        }
    }
    return undef;
}


# --------------------------------------------------------------------
sub extract_PEM(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $name = $args{'name'};
    my $blub = $args{'data'};

    print STDERR "extract_PEM($file, $name, $blub)\n" if($DEBUG);
    # no pwcb needed here...
    $name = $file unless(defined($name) and length($name));
    if(defined($file) and $file =~ /^.+\.${rx_cert_pem}$/ and -f $file) {
        $blub = '';
        if(open(PEM, "<", $file)) {
            while(<PEM>) {
                $blub .= $_;
            }
            close(PEM);
        }
    }
    return undef unless(defined($blub) and length($blub));

    my @list = ();
    my $info = undef;
    my $data = undef;

    # FIXME: use multiline matches?
    for my $line (split(/\n/, $blub)) {
        if(defined($info)) {
            $data .= "$line\n";
            if($line =~ /^[-]{5}END[ ]([A-Z0-9 ]+)+[-]{5}$/) {
                if($info eq $1) {
                    push(@list, {
                            info => $info,
                            data => $data,
                            name => $name,
                        });
                }
                $info = undef;
                $data = undef;
            }
        } else {
            if($line =~ /^[-]{5}BEGIN[ ]([A-Z0-9 ]+)+[-]{5}$/) {
                $info = "$1";
                $data = "$line\n";
            }
        }
    }

    return \@list;
}


# --------------------------------------------------------------------
sub extract_DER(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};
    my $name = $args{'name'};

    print STDERR "extract_DER($file, $pwcb, $name)\n" if($DEBUG);
    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    return undef unless(defined($file) and length($file) and
                        -f $file and $file =~ /^.+\.${rx_cert_der}$/);
    $name = $file unless(defined($name) and length($name));

    #
    # FIXME: keys in DER format requires passwd...?
    #

    my $pass = undef;
    #my $pass &$pwcb(_("Password for ").$name);
    #return undef  unless(defined($pass));

    # FIXME: not required to convert...

    my $ossl = new OPENSSL();
    my $blub;
    if($ossl) {
       $blub = $ossl->convert(
            DATATYPE  =>'CERTIFICATE',
            PASSWD    => $pass,
            INFORM    => "DER",
            INFILE    => $file,
            OUTFORM   => "PEM"
        );
    }
    unless($blub) {
        print STDERR "ERROR: $OPENSSL::errmsg\n" if($DEBUG);
        return undef;
    }
    return extract_PEM(data => $blub, name => $file);
}


# --------------------------------------------------------------------
sub extract_P12(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};
    my $name = $args{'name'};

    print STDERR "extract_P12($file, $pwcb, $name)\n" if($DEBUG);
    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    return undef unless(defined($file) and length($file) and
                        -f $file and $file =~ /^.+\.${rx_pk12_ext}$/);
    $name = $file unless(defined($name) and length($name));

    my $pass = undef;
    my $blub = undef;
    do {
        if(defined($pass)) {
            $pass = &$pwcb(_("Wrong password.")."\n".
                           _("PKCS12 import password for ").$name);
        } else {
            $pass = &$pwcb(_("PKCS12 import password for ").$name);
        }
        return undef unless(defined($pass));

        my $ossl = new OPENSSL();
        if($ossl) {
            $blub = $ossl->convert(
                DATATYPE  =>'CERTIFICATE',
                P12PASSWD => $pass,
                INFORM    => "PKCS12",
                INFILE    => $file,
                OUTFORM   => "PEM"
            );
        } else {
            $blub = undef;
        }
    } while(not $blub);
    unless($blub) {
        print STDERR "ERROR: $OPENSSL::errmsg\n" if($DEBUG);
        return undef;
    }
    return extract_PEM(data => $blub, name => $file);
}


# --------------------------------------------------------------------
sub extract_ZIP(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};
    my $name = $args{'name'};

    print STDERR "extract_ZIP($file, $pwcb, $name)\n" if($DEBUG);
    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    return undef unless(defined($file) and length($file) and
                        -f $file and $file =~ /^.+\.zip$/);

    my @list = ();
    my $zip = Archive::Zip->new($file);
    for my $member ($zip->members()) {
        next unless(defined($member->fileName()));
        next if($member->uncompressedSize() > $ZIP_MAX_SIZE);

        my $name = $member->externalFileName();
        unless(defined($name) and length($name)) {
            $name = $member->fileName();
        }

        if($member->fileName() =~ /\.${rx_cert_pem}$/) {
            my $lref = extract_PEM(data => $member->contents(),
                                   name => $name);
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
                    my $lref = extract_P12(file => $fn,
                                           pwcb => \&{$pwcb},
                                           name => $name);
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
