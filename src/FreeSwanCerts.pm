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
use Fcntl;
use File::Temp qw/ tempfile tempdir /;
use Locale::gettext;
require Exporter;

our @ISA         = qw (Exporter);
#
# FIXME: exports
#
our @EXPORT      = qw (list_CAs list_CERTs list_KEYs list_files write_file
                       parse_cert parse_crl parse_key parse_pem_data
                       extract_ANY extract_ZIP extract_P12 extract_PEM
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
our $rx_pk12_ext  = qr /(?:p12|pk12|pfx)/io;


#
# === public functions ===============================================
#
sub list_CAs($;$)
{
    my $openssl = shift;
    my $dir  = shift || $DEFS{'ipsec_cacerts'};
    my %certs;

    foreach my $file (list_files($dir)) {
        my $cert = parse_cert($openssl, file => $file);
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
        my $cert = parse_crl($openssl, file => $file);
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
        my $cert = parse_cert($openssl, file => $file);
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
#        my $cert = parse_key($openssl, file => $file);
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
# openssl, {file => name, data => ...}
sub parse_cert($%)
{
    my $openssl = shift;
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

    my $X509 = new OpenCA::X509(DATA  =>$indata,
                                INFILE=>$infile,
                                INFORM=>$inform,
                                SHELL =>$openssl);
    unless($X509) {
        # FIXME: use err from X509 ?
        print STDERR "ERROR: unable to parse cert",
                     defined($infile) ? " '$infile'" : "",
                     ": errno=$OpenCA::X509::errno,",
                     " errval=$OpenCA::X509::errval\n" if($DEBUG);
        return undef;
    }

    my $parsed = $X509->getParsed();
    my $subjaltname = undef;

    #print STDERR "CERT PARSED: ", join(", ", keys %{$parsed}), "\n";

    if(exists($parsed->{"OPENSSL_EXTENSIONS"}) and
       ref($parsed->{"OPENSSL_EXTENSIONS"}) eq 'HASH') {
        my $ref = $parsed->{"OPENSSL_EXTENSIONS"};

       #print STDERR "CONSTRAINS: ", @{$ref->{"X509v3 Basic Constraints"}},
       #"\n";

       #print STDERR "BASIC IS_CA(",$infile||'',") => ",
       #      $parsed->{"EXTENSIONS"}->{"BASIC_CONSTRAINTS"}->{"CA"}, "\n";

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

    print STDERR "IS_CA(",$infile||'',") => ",  $parsed->{"IS_CA"}, "\n";

    my %cert;
    $cert{"IS_CA"}         = $parsed->{"IS_CA"};
    $cert{"DN"}            = $parsed->{"DN"};
    $cert{"ISSUER"}        = $parsed->{"ISSUER"};
    $cert{"subjectAltName"}= $subjaltname;
    return \%cert;
}

# --------------------------------------------------------------------
# openssl, {file => name, data => ...}
sub parse_crl($%)
{
    my $openssl = shift;
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
 
    my $CRL = new OpenCA::CRL(DATA  =>$indata,
                              INFILE=>$infile,
                              SHELL =>$openssl);
    unless($CRL) {
        print STDERR "ERROR: unable to parse crl",
                     defined($infile) ? "'$infile'" : "",
                     ": $!\n" if($DEBUG);
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

            print STDERR "SubjectAltName(", $infile||'',
                         "): $subjaltname\n" if($DEBUG);

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
# openssl, {file => name, data => ..., pass => ...}
sub parse_key($%)
{
    my $openssl = shift;
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
    my %hash;
    $hash{"PASSWORD"} = $passwd;
    return \%hash;
}

# --------------------------------------------------------------------
sub parse_pem_data($%)
{
    my $openssl = shift;
    my %args    = @_;
    my $data    = $args{'data'};
    my $info    = $args{'info'};
    my $pwcb    = $args{'pwcb'}; # need it for key...

    my $type    = pem_type_by_string($info);
    if(defined($type)) {
        if('KEY'  eq $type) {
            return {
                type => $type,
                hash => parse_key ($openssl, data => $data)
            };
        }
        if('CRL'  eq $type) {
            return {
                type => $type,
                hash => parse_crl ($openssl, data => $data)
            };
        }
        if('CERT' eq $type) {
            return {
                type => $type,
                hash => parse_cert($openssl, data => $data)
            };
        }
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

sub is_certificate($)
{
# if /------BEGIN CERTIF/ ...
	return 1;
}

our %save_certificates;
our @delete_certificates;

##
 # schedule a certificate to be saved under /etc/ipsed.d/certifiates
 # @param absolute filename of file to import, e.g. /floppy/foo.pem
 # @param filename to store it as, e.g. cert.pem
sub save_certificate_as($$)
{
    my $filename = shift;
    my $saveas = shift;

    $save_certificates{$saveas} = $filename;
}

sub delete_certificae($)
{
    my $name = shift;
    push @delete_certificates, $name;
}


# copy a file
sub do_cp($$)
{
    my $from = shift;
    my $to = shift;

    my @cmd = ('/bin/cp', $from, $to);

    system @cmd or return sprintf(_("Could not copy %s to %s\n"), $from, $to);
    return undef;
}

# copy certificates, crls, keys etc to /etc/ipsec.d
sub commit_scheduled_file_operations()
{
    my $saveas;
    my @errors;
    foreach $saveas (keys %save_certificates)
    {
	my $err = do_cp($save_certificates{$saveas}, $DEFS{'ipsec_certs'}.'/'.$saveas);
	push @errors, $err if(defined $err);
    }
#TODO more
    return \@errors;
}


# --------------------------------------------------------------------
sub write_file($$$)
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
        return "can't write '$file': $!";
    }
    return "invalid arguments";
}

# --------------------------------------------------------------------
sub extract_ANY(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};

    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    if(defined($file) and length($file) and -f $file) {
        if($file =~ /^.+\.zip$/io) {
            return extract_ZIP(file => $file, pwcb => $pwcb);
        }
        if($file =~ /^.+\.${rx_pk12_ext}$/) {
            return extract_P12(file => $file, pwcb => $pwcb);
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
sub extract_P12(%)
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};
    my $name = $args{'name'};

    return undef unless(defined($pwcb) and ref($pwcb) eq 'CODE');
    return undef unless(defined($file) and length($file) and
                        -f $file and $file =~ /^.+\.${rx_pk12_ext}$/);
    $name = $file unless(defined($name) and length($name));

    my $pass = &$pwcb(_("PKCS12 export password for ").$name);
    return undef  unless(defined($pass));

    # FIXME: openssl instance?
    my $openssl = new OpenCA::OpenSSL(SHELL => "/usr/bin/openssl");
    if($openssl) {
        my $blub    = $openssl->dataConvert(
            DATATYPE  =>'CERTIFICATE',
            P12PASSWD => $pass,
            INFORM    => "PKCS12",
            INFILE    => $file,
            OUTFORM   => "PEM",
        );
        return extract_PEM(data => $blub, name => $file);
    }
    return undef;
}


# --------------------------------------------------------------------
sub extract_ZIP
{
    my %args = @_;
    my $file = $args{'file'};
    my $pwcb = $args{'pwcb'};
    my $name = $args{'name'};

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
