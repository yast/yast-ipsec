# -*- perl -*-
#
# File:         modules/FreeSwanUtils.pm
# Package:      Configuration of ipsec
# Summary:      FreeS/WAN IPSec utilities
# Authors:      Marius Tomaschewski <mt@suse.de>
#
# $Id$
#
package FreeSwanUtils;
use 5.008000;
use strict;
use warnings;
use Fcntl qw(:DEFAULT :mode :flock);
use File::Glob ':glob';

our $VERSION     = 0.1;
our $DEBUG       = 0;  # level 0 .. 4
our $DEPTH       = 10; # default from ipsec.secrets(5)
our %DEFS        = (
    'ipsec_version'  => '2.0',
    'ipsec_root'     => '',
    'ipsec_conf'     => '/etc/ipsec.conf',
    'ipsec_secrets'  => '/etc/ipsec.secrets',
    'ipsec_dir'      => '/etc/ipsec.d',
    'ipsec_policies' => '/etc/ipsec.d/policies',
    'ipsec_crls'     => '/etc/ipsec.d/crls',
    'ipsec_cacerts'  => '/etc/ipsec.d/cacerts',
    'ipsec_private'  => '/etc/ipsec.d/private',
);

our @CONN_DEFAULTS = qw(%default);
our @CONN_IMPLICIT = qw(clear block private packetdefault
                        clear-or-private private-or-clear OEself);

## unused at the moment
our $rx_keyword = qr /[a-zA-Z][a-zA-Z0-9_-]*/o;
our $rx_kv_line = qr /^[ \t]+(${rx_keyword})[ \t]*=[ \t]*(.*)[ \t]*$/o;
our $rx_is_conn = qr /^conn[ \t]+(${rx_keyword}|%default)[ \t]*$/o;
our $rx_isspace = qr /\S/o;
our $rx_isempty = qr /^\s*$/o;
our $rx_isquote = qr /[\"\s]/o;
our $rx_vquoted = qr /^\"([^\"]*)\"$/o;


#
# === public interface ===============================================
#
sub new
{
    my $type = shift;
    my %args = @_;
    my $self = {};

    for my $key (keys %DEFS) {
        $self->{$key} = $args{$key} ? $args{$key} : $DEFS{$key};
    }
    error($self, undef);
    _init_config($self);
    _init_secrets($self);
    return bless($self, ref($type) || $type);
}


#
# --------------------------------------------------------------------
#
sub error
{
    my $self = shift;
    if(@_ > 0) {
        if(defined($_[0])) {
            return exists($self->{'error'}->{$_[0]}) ?
                   $self->{'error'}->{$_[0]} : undef;
        } else {
            $self->{'error'} = {code=>0};
        }
    } else {
        return wantarray ? %{$self->{'error'}} :
               $self->{'error'}->{'code'} || 0;
    }
}


#
# --------------------------------------------------------------------
#
sub errstr
{
    my $self = shift;

    my $err  = '';
    if($self->{'error'}->{'code'}) {
        $err  = "ERROR[".$self->{'error'}->{'code'}."]: ";
        $err .= $self->{'error'}->{'emsg'};
        if($self->{'error'}->{'file'}) {
            $err .= " in ".$self->{'error'}->{'file'};
            if($self->{'error'}->{'code'} > 0) {
               $err .= ":".$self->{'error'}->{'code'};
            }
        }
        $err .= $self->{'error'}->{'erno'} ?
                " [errno=".$self->{'error'}->{'erno'}."]" : "";
        $err .= $self->{'error'}->{'line'} ?
                " line='".$self->{'error'}->{'line'}."'"  : "";
    }
    return $err;
}


#
# --------------------------------------------------------------------
#
sub load_config
{
    my $self = shift;
    my $file = shift;

    unless($file) {
        $file = $self->{'ipsec_root'}.
                $self->{'ipsec_conf'};
        unless(-f $file) {
            #
            # fake empty default config
            # if it does not exists
            #
            $self->_init_config(file   => $file,
                                setup  => {},
                                conn   => {
                                    '%default' => {
                                        'file' => $file,
                                        'data' => {}
                                    }
                                },
                                version=> $self->{'ipsec_version'});
            return 1; # true
        }
    }
    $self->_init_config(file => $file);

    my ($ret, %err) = load_ipsec_config(\%{$self->{'conf'}}, $file, $DEPTH);
    if ($ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "LOAD ", $self->errstr(), "\n" if($DEBUG>0);
        $self->_init_config();
        return 0; # false
    } else {
        $self->error(undef);
        return 1; # true
    }
    return $ret;
}


#
# --------------------------------------------------------------------
#
sub save_config
{
    my $self = shift;

    my ($ret, %err) = save_ipsec_config(\%{$self->{'conf'}},
                                        $self->{'ipsec_version'});
    $self->_init_config();
    if( $ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "SAVE ", $self->errstr(), "\n" if($DEBUG>0);
        return 0; # false
    } else {
        $self->error(undef);
        return 1; # true
    }
}


#
# --------------------------------------------------------------------
#
sub dump_config
{
    my $self = shift;
    my $file = shift;

    return dump_ipsec_config(\%{$self->{'conf'}}, $file,
                             $self->{'ipsec_version'});
}


#
# --------------------------------------------------------------------
#
sub load_secrets
{
    my $self = shift;
    my $file = shift;

    unless($file) {
        $file = $self->{'ipsec_root'}.
                $self->{'ipsec_secrets'};
        unless(-f $file) {
            #
            # fake empty default config
            # if it does not exists
            #
            $self->_init_secrets(file   => $file);
            return 1; # true
        }
    }
    $self->_init_secrets(file => $file);

    my ($ret, %err) = load_ipsec_secrets(\%{$self->{'secr'}}, $file, $DEPTH);
    if ($ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "LOAD ", $self->errstr(), "\n" if($DEBUG>0);
        $self->_init_secrets();
        return 0; # false
    } else {
        $self->error(undef);
        return 1; # true
    }
    return $ret;
}


#
# --------------------------------------------------------------------
#
sub save_secrets
{
    my $self = shift;

    my ($ret, %err) = save_ipsec_secrets(\%{$self->{'secr'}});
    $self->_init_secrets();
    if( $ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "SAVE ", $self->errstr(), "\n" if($DEBUG>0);
        return 0; # false
    } else {
        $self->error(undef);
        return 1; # true
    }
    return 1; # true
}


#
# --------------------------------------------------------------------
#
sub dump_secrets
{
    my $self = shift;
    my $file = shift;

    return dump_ipsec_secrets(\%{$self->{'secr'}}, $file);
}


#
# --------------------------------------------------------------------
#
sub setup { settings(@_); }
sub settings
{
    my $self = shift;
    my $conf = \%{$self->{'conf'}};
    my @args = @_;
    if(@args > 0) {
        if(@args % 2) {
            if(exists($conf->{'setup'}) and
               exists($conf->{'setup'}->{$args[0]})) {
                return $conf->{'setup'}->{$args[0]};
            }
        } else {
            for(my $at=0; $at<=$#args; $at += 2) {
                next unless($args[$at]);
                if(defined($args[$at+1]) and $args[$at+1] =~ /\S+/) {
                    $conf->{'setup'}->{$args[$at]} = $args[$at+1];
                } else {
                    delete($conf->{'setup'}->{$args[$at]});
                }
            }
        }
    } else {
        # note: setup may be undef (not loaded)!
        if(exists($conf->{'setup'})) {
            if(wantarray) {
                return %{$conf->{'setup'}};
            } else {
                return   $conf->{'setup'};
            }
        }
        return wantarray ? () : undef;
    }
}

#
# --------------------------------------------------------------------
#
sub conns { connections(@_); }
sub connections
{
    my $self = shift;
    my $conf = \%{$self->{'conf'}};
    my %args = @_;
    my @excl = ();
    my @incl = ();

    foreach my $arg (keys %args) {
        if($arg eq 'exclude' and 'ARRAY' eq ref($args{$arg})) {
            foreach (@{$args{$arg}}) {
                push(@excl, $_ eq '%implicit' ?
                            @CONN_IMPLICIT : $_);
            } next;
        }
        if($arg eq 'include' and 'ARRAY' eq ref($args{$arg})) {
            foreach (@{$args{$arg}}) {
                push(@incl, $_ eq '%implicit' ?
                            @CONN_IMPLICIT : $_);
            } next;
        }
    }

    my @list = ();
    for my $name (keys %{$conf->{'conn'} || {}}) {
        unless(scalar(keys %{$conf->{'conn'}->{$name}->{'data'}||{}})) {
            # skip deleted/empty conns
            next;
        }
        if(grep($name eq $_, @incl)) {
            # explicitely included
            push(@list, $name);
            next;
        }
        if(grep($name eq $_, @excl)) {
            next;
        }
        push(@list, $name);
    }
    return sort(@list);
}

# --------------------------------------------------------------------
sub conn  { connection(@_); }
sub connection
{
    my $self = shift;
    my $conf = \%{$self->{'conf'}};
    my $name = shift;
    my @args = @_;
    my $conn = \%{$conf->{'conn'}};
    if(@args > 0) {
        if(@args % 2) {
            #
            # get value ->conn('foo', 'auto')
            #
            if($args[0] and exists($conn->{$name}) and
               exists($conn->{$name}->{'data'}->{$args[0]})) {
                return $conn->{$name}->{'data'}->{$args[0]};
            }
        } else {
            #
            # set value ->conn('foo', 'auto' => 'ignore')
            #
            unless(exists($conn->{$name})) {
                $conn->{$name} = { 'file' => undef, 'data' => {} };
            } else {
                $conn->{$name}->{'data'} = {};
            }
            for(my $at=0; $at<=$#args; $at += 2) {
                next unless($args[$at] and
                            $args[$at] =~ /^${rx_keyword}$/);
                if(defined($args[$at+1]) and
                   $args[$at+1] =~ /\S+/ and
                   $args[$at+1] =~ /[^\"]/) {
                    $conn->{$name}->{'data'}->{$args[$at]} = $args[$at+1];
                }
            }
        }
    } else {
        #
        # get data of conn $name as
        #   hash copy: %foo = ->conn('foo')
        #   hash ref : $foo = ->conn('foo')
        #
        if(exists($conn->{$name}) and $conn->{$name}->{'data'}) {
            if(wantarray) {
                return %{$conn->{$name}->{'data'}};
            } else {
                return   $conn->{$name}->{'data'};
            }
        }
        return wantarray ? () : undef;
    }
}

# --------------------------------------------------------------------
sub conn_delete
{
    my $self = shift;
    my $name = shift;
    my $conf = \%{$self->{'conf'}};
    my $conn = \%{$conf->{'conn'}};

    if(exists($conn->{$name}) and not(grep($name eq $_,
       (@CONN_IMPLICIT, @CONN_DEFAULTS)))) {
        return delete($conn->{$name});
    }
    return undef;
}

# --------------------------------------------------------------------
sub secrets
{
    my $self = shift;
    my %args = @_;
    my $secr = \%{$self->{'secr'}};
    my @list = ();

    my $type = $args{'type'};
    for my $kref (@{$secr->{'keys'} || []}) {
        if(defined($type)) {
            next unless(uc($kref->{'type'}) eq uc($type));
        }
        my %copy = %{$kref};
        if(defined($copy{'x509'}) and $copy{'x509'} !~ /^\//) {
            $copy{'x509'} = $DEFS{'ipsec_private'}.'/'.$copy{'x509'};
        }
        push(@list, \%copy);
    }
    return sort @list;
}

# --------------------------------------------------------------------
sub secret_get
{
    my $self = shift;
    my %args = @_;
    my $secr = \%{$self->{'secr'}};

    my $type = $args{'type'};
    my $x509 = $args{'x509'};
    my $index= $args{'index'};
    if(defined($index)) {
        $index = '%any'  if($index eq '' and not defined($x509));
        $index = '%any'  if($index eq '0.0.0.0');
        $index = '%any6' if($index eq '::');
    }
    for(my $i=0; $i<scalar(@{$secr->{'keys'} || []}); $i++) {
        my $kref = $secr->{'keys'}->[$i];
        if(defined($type)) {
            next unless(uc($kref->{'type'}) eq uc($type));
        }
        if(defined($x509)) {
            next unless(defined($kref->{'x509'}));
            my $file = $kref->{'x509'};
            if($file !~ /^\//) {
               $file = $DEFS{'ipsec_private'}.'/'.$file;
            }
            if($file eq $x509) {
                return $kref;
            }
        }
        if(defined($index)) {
            my $itemp = $kref->{'index'};
            $itemp = '%any'  if($itemp eq '' and not defined($x509));
            $itemp = '%any'  if($itemp eq '0.0.0.0');
            $itemp = '%any6' if($itemp eq '::');
            if($index eq $itemp) {
                return $kref;
            }
        }
    }
    return undef;
}

# --------------------------------------------------------------------
sub secret_set
{
    my $self = shift;
    my %args = @_;
    my $secr = \%{$self->{'secr'}};
    my %nkey = ();
    my $kref;

    # apply default index if not given
    $args{'index'} = '' unless(defined($args{'index'}));

    unless(defined($args{'type'}) and $args{'type'} =~ /^(?:RSA|PSK)$/i) {
        return undef; # type is mandatory
    }

    if(uc($args{'type'}) eq 'RSA') {

        # check required values
        if(defined($args{'x509'})) {
            return undef unless(defined($args{'pass'}) and $args{'x509'} =~ /^\S+/);
        } else {
            return undef unless(defined($args{'data'}) or 'HASH' eq ref($args{'hash'}));
        }

        if($args{'x509'}) {
            #
            # RSA x509
            #
            $nkey{'index'} = $args{'index'};
            $nkey{'type'}  = 'RSA';
            $nkey{'x509'}  = $args{'x509'};
            $nkey{'pass'}  = $args{'pass'};
            $nkey{'hash'}  = undef;
            $nkey{'data'}  = undef;
            $kref = $self->secret_get('type' => 'RSA',
                                      'x509' => $nkey{'x509'});
        } else {
            #
            # RSA {...}
            #
            my $data = '';
            my %hash = ();
            my %want = (modulus=>0, exponent1=>0, exponent2=>0,
                        privateexponent=>0, publicexponent=>0,
                        coefficient=>0, prime1=>0, prime2=>0);

            if(ref($args{'hash'}) eq 'HASH') {
                for my $key (keys %{$args{'hash'}}) {
                    my $val = $args{'hash'}->{$key};
                    if(defined($val)
                       and $val = /^\S+$/
                       and exists($want{lc($key)})
                       and (0 == $want{lc($key)})) {
                        $want{lc($key)} = 1;
                        $hash{$key} = $val;
                        $data .= "\t".$key.": ".$val;
                    }
                }
            } else {
                my $data = $args{'data'} || '';
                my $temp = $data;
                while($temp =~ s/^\s+(\S+):\s+(\S+)//) {
                    my ($key, $val) = ($1, $2);
                    if(exists($want{lc($key)})) {
                        $want{lc($key)} = 1;
                        $hash{$key} = $val;
                    }
                }
            }
            # abort if a key component missed
            for my $val (values %want) {
                return undef if(0 == $val);
            }
            $nkey{'index'} = $args{'index'};
            $nkey{'type'}  = 'RSA';
            $nkey{'x509'}  = undef;
            $nkey{'pass'}  = undef;
            $nkey{'hash'}  = {%hash};
            $nkey{'data'}  = $data;
            $kref = $self->secret_get('type' => 'RSA',
                                      'index' => $nkey{'index'});
        }
    } else {
        # check required values
        return undef unless(defined($args{'pass'}) and defined($args{'index'}));

        #
        # PSK
        #
        $nkey{'index'} = $args{'index'};
        $nkey{'type'}  = 'PSK';
        $nkey{'pass'}  = $args{'pass'};
        $nkey{'x509'}  = undef;
        $nkey{'hash'}  = undef;
        $nkey{'data'}  = undef;
        $kref = $self->secret_get('type'  => 'PSK',
                                  'index' => $nkey{'index'});
    }

    if(defined($kref)) {
        #
        # just update kref
        #
        %{$kref} = %nkey;
    } else {
        #
        # add a new secret
        #
        push(@{$secr->{'keys'}}, {%nkey});
    }
    return \%nkey;
}

# --------------------------------------------------------------------
sub secret_del
{
    my $self = shift;
    my %args = @_;
    my $secr = \%{$self->{'secr'}};

    my $type = $args{'type'};
    my $x509 = $args{'x509'};
    my $index= $args{'index'};
    if(defined($index)) {
        $index = '%any'  if($index eq '' and not defined($x509));
        $index = '%any'  if($index eq '0.0.0.0');
        $index = '%any6' if($index eq '::');
    }
    for(my $i=0; $i<scalar(@{$secr->{'keys'} || []}); $i++) {
        my $kref = $secr->{'keys'}->[$i];
        if(defined($type)) {
            next unless(uc($kref->{'type'}) eq uc($type));
        }
        if(defined($x509)) {
            next unless(defined($kref->{'x509'}));
            my $file = $kref->{'x509'};
            if($file !~ /^\//) {
               $file = $DEFS{'ipsec_private'}.'/'.$file;
            }
            if($file eq $x509) {
                splice(@{$secr->{'keys'}}, $i, 1);
                return $kref;
            }
        }
        if(defined($index)) {
            my $itemp = $kref->{'index'};
            $itemp = '%any'  if($itemp eq '' and not defined($x509));
            $itemp = '%any'  if($itemp eq '0.0.0.0');
            $itemp = '%any6' if($itemp eq '::');
            if($index eq $itemp) {
                splice(@{$secr->{'keys'}}, $i, 1);
                return $kref;
            }
        }
    }
    return undef;
}

# --------------------------------------------------------------------
sub is_valid_conn_name
{
    my $self = shift;
    my $name = shift;
    if(defined($name) and $name =~ /^${rx_keyword}$/) {
        if(grep($name eq $_, @CONN_IMPLICIT)) {
            return 2;
        }
        return 0; # OK
    }
    return 1;
}


#
# === private functions ==============================================
#
sub _init_config
{
    my $self = shift;
    my %args = @_;
    my %conf = (
        'version' => undef,
        'include' => [],
        'setup'   => undef,
        'conn'    => {},
        'file'    => undef,
    );
    $self->{'conf'} = {};
    foreach (keys %conf) {
        $self->{'conf'}->{$_} = exists($args{$_}) ?
                                $args{$_} : $conf{$_};
    }
}

#
# --------------------------------------------------------------------
#
sub _init_secrets
{
    my $self = shift;
    my %args = @_;
    my %secr = (
        'include' => [],
        'keys'    => [],
        'file'    => undef,
    );
    $self->{'secr'} = {};
    foreach (keys %secr) {
        $self->{'secr'}->{$_} = exists($args{$_}) ?
                                $args{$_} : $secr{$_};
    }
}

#
# --------------------------------------------------------------------
#
sub load_ipsec_config
{
    my $conf = shift;
    my $file = shift;
    my $dpth = shift;

    unless($file and $file =~ /\S+/ and -f $file) {
        return (-1, emsg=>"invalid file name", file=>$file);
    }

    if(open(CONF, '<', $file)) {
        my @data = <CONF>;
        close(CONF);

        my ($ret, %err) = _load_ipsec_config($conf, $file,
                                             $dpth, \@data);
        return ($ret, %err) if(0 != $ret);
    } else {
        return (-2, emsg=>"can't open file",
                    file=>$file, erno=>$!);
    }
}


#
# --------------------------------------------------------------------
#
sub save_ipsec_config
{
    my $conf = shift;
    my $_ver = shift || $DEFS{'ipsec_version'};
    my $file = $conf->{'file'};

    unless($file and exists($conf->{'version'})) {
        return (-1, emsg=>"invalid arguments");
    }

    $conf->{'version'} = $_ver unless($conf->{'version'});
    for my $conn (keys %{$conf->{'conn'}}) {
        unless($conf->{'conn'}->{$conn}->{'file'}) {
            $conf->{'conn'}->{$conn}->{'file'} = $conf->{'file'};
        }
    }

    my $save = {};
    my ($ret, %err) = _save_ipsec_config($conf, $file, $save,
                                         \&_backup_and_read);
    if(0 == $ret) {
        my $data = $save->{$file};

        if(scalar(@{$data || []})) {
            # included files
            for my $_file (keys %{$save}) {
                next if($file eq $_file);

                my $_data = $save->{$_file};
                if(scalar(@{$_data || []})) {
                    unlink($_file) if(-f $_file);
                    if(sysopen(CONF, $_file, O_RDWR|O_CREAT|O_EXCL, 0644)) {
                        for my $line (@{$_data}) {
                            print CONF "$line\n";
                        }
                        close(CONF);
                    } else {
                        return (-2, emsg=>"can't write config file",
                                    file=>$_file, erno=>$!);
                    }
                } # else unlink $_file ?
            }

            # main config
            unlink($file) if(-f $file);
            if(sysopen(CONF, $file, O_RDWR|O_CREAT|O_EXCL, 0644)) {
                for my $line (@{$data}) {
                    print CONF "$line\n";
                }
                close(CONF);
                return (0); ### SUCCEED!
            } else {
                return (-2, emsg=>"can't write config file",
                            file=>$file, erno=>$!);
            }
        } else {
            return (-1, emsg=>"empty content?!");
        }
    }
    return ($ret, %err);
}


#
# --------------------------------------------------------------------
#
sub save_ipsec_secrets
{
    my $secr = shift;
    my $file = $secr->{'file'};

    unless($file) {
        return (-1, emsg=>"invalid arguments");
    }

    my $save = {};
    my ($ret, %err) = _save_ipsec_secrets($secr, $file, $save,
                                          \&_backup_and_read);
    if(0 == $ret) {
        my $data = $save->{$file};

        # included files first
        for my $_file (keys %{$save}) {
            next if($file eq $_file);

            my $_data = $save->{$_file};
            unlink($_file) if(-f $_file);
            if(sysopen(SECR, $_file, O_RDWR|O_CREAT|O_EXCL, 0600)) {
                for my $line (@{$_data}) {
                    print SECR "$line\n";
                }
                close(SECR);
            } else {
                return (-2, emsg=>"can't write secret file",
                            file=>$_file, erno=>$!);
            }
        }

        # main secrets
        unlink($file) if(-f $file);
        if(sysopen(SECR, $file, O_RDWR|O_CREAT|O_EXCL, 0600)) {
            for my $line (@{$data}) {
                print SECR "$line\n";
            }
            close(SECR);
            return (0); ### SUCCEED!
        } else {
            return (-2, emsg=>"can't write secret file",
                        file=>$file, erno=>$!);
        }
    }
    return ($ret, %err);
}


#
# --------------------------------------------------------------------
#
sub dump_ipsec_config
{
    my $conf = shift;
    my $file = shift || $conf->{'file'};
    my $_ver = shift || $DEFS{'ipsec_version'};
    my $sect;
    my @temp;
    my @data = ();
    my $eol;

    return () unless($conf and $file and
                     exists($conf->{'version'}));

    push(@data, "#< $file", "");
    if($file eq $conf->{'file'}) {

        if($conf->{'version'}) {
            push(@data, "version ". $conf->{'version'}, "");
        } else {
            push(@data, "version ". $_ver, "");
        }

        push(@data, "config setup");
        foreach (_dump_section($conf->{'setup'})) {
            push(@data, "$_");
        }
        push(@data, "");

        push(@data, "conn \%default");
        if(exists($conf->{'conn'}->{'%default'})) {
            $sect = $conf->{'conn'}->{'%default'}->{'data'};
            foreach (_dump_section($sect)) {
                push(@data, "$_");
            }
        }
        push(@data, "");
    }

    #
    # ipsec.conf(5) says "the implicit conns are
    # defined after all others" -- try to do it.
    #
    CONN: for my $name (keys %{$conf->{'conn'}}) {
        next unless($name =~ /^\S+$/);
        for my $skip (@CONN_DEFAULTS, @CONN_IMPLICIT) {
            next CONN if($skip eq $name);
        }

        my $sect = $conf->{'conn'}->{$name}->{'data'} || {};
        my $curr = $conf->{'conn'}->{$name}->{'file'};
        unless($curr) {
            $curr = $file if($file eq $conf->{'file'});
        }

        if($curr eq $file and scalar(keys %{$sect})) {
            push(@data, "conn $name");
            foreach (_dump_section($sect)) {
                push(@data, "$_");
            }
            push(@data, "");
        }
    }

    $eol = 0;
    for my $incl (@{$conf->{'include'} || []}) {
        if($file eq $incl->{'file'} and
           $incl->{'incl'} =~ /\S+/) {
            $eol = 1;
            push(@data, "include ". $incl->{'incl'});
        }
    }
    push(@data, "") if($eol);

    for my $name (@CONN_IMPLICIT) {
        next unless($name =~ /^\S+$/);
        next unless(exists($conf->{'conn'}->{$name}));

        my $sect = $conf->{'conn'}->{$name}->{'data'} || {};
        my $curr = $conf->{'conn'}->{$name}->{'file'};
        unless($curr) {
            $curr = $file if($file eq $conf->{'file'});
        }

        if($curr eq $file and scalar(keys %{$sect})) {
            push(@data, "conn $name");
            foreach (_dump_section($sect)) {
                push(@data, "$_");
            }
            push(@data, "");
        }
    }
    push(@data, "#> $file");
    return @data;
}


#
# --------------------------------------------------------------------
#
sub _dump_section
{
    my $sect = shift;
    my @temp = ();

    foreach my $key (sort keys %{$sect || {}}) {
        my $val = $sect->{$key} || '';
        if($key =~ /^\S+$/ and $val =~ /\S+/) {
            if($val =~ /\s+/) {
                $val = '"' . $val . '"';
            }
            push(@temp, "\t$key=".$val);
        }
        delete($sect->{$key});
    }
    return @temp;
}


#
# --------------------------------------------------------------------
#
sub dump_ipsec_secrets
{
    my $secr = shift;
    my $file = shift || $secr->{'file'};
    my @data = ();
    my $eol;

    return () unless($secr and $file);

    push(@data, "#< $file", "");
    $eol = 0;
    for my $kref (@{$secr->{'keys'} || []}) {
        if(($kref->{'file'} || $secr->{'file'}) ne $file) {
            next;
        }
        $eol = 1;
        if($kref->{'type'} eq 'RSA') {
            if($kref->{'x509'}) {
                unless(defined($kref->{'pass'})) {
                    $kref->{'pass'} = '';
                }
                push(@data, $kref->{'index'}.': RSA '.
                            $kref->{'x509'} .' "'.
                            $kref->{'pass'} .'"');
            } else {
                my $kdata = $kref->{'data'};
                push(@data, $kref->{'index'}.": RSA {");
                while($kdata =~ s/^\s+(\S+:\s+\S+)//) {
                    push(@data, "\t".$1);
                }
                push(@data, "\t}");
            }
        } else {
            unless(defined($kref->{'pass'})) {
                $kref->{'pass'} = '';
            }
            push(@data, $kref->{'index'}.': PSK "'.
                        $kref->{'pass'}.'"');
        }
    }
    push(@data, "") if($eol);

    $eol = 0;
    for my $iref (@{$secr->{'include'}}) {
        if(($iref->{'file'} || $secr->{'file'}) ne $file) {
            next;
        }
        $eol = 1;
        push(@data, "include ". $iref->{'incl'});
    }
    push(@data, "") if($eol);

    push(@data, "#> $file", "");
    return @data;
}


#
# --------------------------------------------------------------------
#
sub _load_ipsec_config
{
    my $conf = shift;
    my $file = shift;
    my $dpth = shift;
    my $data = shift;
    my $lnum = 0;
    my $sect = undef;

    unless($conf and $file and $data) {
        return (-1, emsg=>"invalid arguments");
    }
    foreach my $line (@{$data || []}) {
        chomp($line);
        $lnum++;

        print STDERR sprintf("LOAD [%s:%02d]: ", $file, $lnum), " $line\n"
            if($DEBUG > 3);

        $line =~ s/#.*$//g;  # strip comments...
        if($line =~ /^$/) {  # empty lines ends a section
            $sect = undef;
            next;
        }

        if($line =~ /^version/) {
            if($conf->{'version'}) {
                return ($lnum, emsg=>"duplicate version",
                               file=>$file, line=>$line);
            }

            if($line =~ /^version[ \t]+(\d+[\d|.]*)[ \t]*$/) {
                $conf->{'version'} = "$1";
            } else {
                return ($lnum, emsg=>"invalid version line",
                               file=>$file, line=>$line);
            }
            $sect = undef;
            next;
        }

        if($line =~ /^include/) {
            my $depth = undef;
            if(defined($dpth)) {
                if(0 >= $dpth) {
                    return (-3, emsg=>"recursion depth reached",
                                file=>$file, line=>$line);
                }
                $depth = $dpth - 1;
            }

            if($line =~ /^include[ \t]+(\S+)[ \t]*$/) {
                my $incl = $1;
                my $full = $incl;
                my $pref = '';
                if($incl !~ /^\//) {
                    $pref = $file;
                    $pref =~ s/[^\/]+$//;
                    $full = $pref . $incl;
                }

                my @list = bsd_glob($full, GLOB_ERR | GLOB_LIMIT);
                if(0 >= scalar(@list)) {
                    return ($lnum, emsg=>"invalid include glob",
                                   file=>$file, line=>$line);
                }
                for my $name (@list) {
                    next unless($name);
                    if(($name eq $file) or ($name eq $conf->{'file'})) {
                        return ($lnum, emsg=>"recursive inclusion",
                                       file=>$file, line=>$line);
                    }

                    print STDERR "INCLUDE '$incl' => $name\n" if($DEBUG>1);

                    my ($ret, %err) = load_ipsec_config($conf, $name, $depth);
                    return ($ret, %err) if(0 != $ret);
                }
                push(@{$conf->{'include'}}, { 'incl' =>  $incl,
                                              'file' =>  $file,
                                              'list' => [@list] });
            } else {
                return ($lnum, emsg=>"invalid include line",
                               file=>$file, line=>$line);
            }
            $sect = undef;
            next;
        }

        if($line =~ /^config/) {
            if($conf->{'setup'}) {
                return ($lnum, emsg=>"duplicate config setup",
                               file=>$file, line=>$line);
            }

            if($line =~ /^config[ \t]+setup[ \t]*$/) {
                $conf->{'setup'} = {};
            } else {
                return ($lnum, emsg=>"invalid config line",
                               file=>$file, line=>$line);
            }
            $sect = \%{$conf->{'setup'}};
            next;
        }

        if($line =~ /^conn/) {
            my $name;
            if($line =~ /^conn[ \t]+(\S+)[ \t]*$/) {
                $name = $1;
            } else {
                return ($lnum, emsg=>"invalid conn line",
                               file=>$file, line=>$line);
            }
            if(exists($conf->{'conn'}->{$name})) {
                return ($lnum, emsg=>"duplicate connection",
                               file=>$file, line=>$line);
            }
            $conf->{'conn'}->{$name}->{'file'} = $file;
            $conf->{'conn'}->{$name}->{'data'} = {};
            $sect = \%{$conf->{'conn'}->{$name}->{'data'}};
            next;
        }

        if($line =~ /^[ \t]+/) {
            next if($line =~ /^[ \t]+$/); # section comment
            if($sect and $line =~ /^[ \t]+(\S+?)[ \t]*=[ \t]*(.*)[ \t]*/) {
                my ($key, $val) = ($1, $2);
                if( $val =~ /^\"([^\"]*)\"$/) {
                    $val =  $1;
                }
                $sect->{$key} = $val if($val =~ /\S+/);
            } else {
                return ($lnum, emsg=>"invalid section line",
                               file=>$file, line=>$line);
            }
        } else {
            return ($lnum, emsg=>"syntax error",
                           file=>$file, line=>$line);
        }
    }
    return (0);
}


#
# --------------------------------------------------------------------
#
sub _save_ipsec_config
{
    my $conf = shift;
    my $file = shift;
    my $save = shift;
    my $read = shift;

    unless($conf and $file and $read) {
        return (-1, emsg=>"invalid arguments");
    }

    my ($ret, $data, $err) = &$read($file);
    if( $ret) {
        return ($ret, emsg=>$data, file=>$file, erno=>$err);
    }

    my @fout = ();      # output data
    my @scom = ();      # comments before a section
    my @kcom = ();      # comments before a keyword
    my $sect = undef;   # reference to current section 
    my $conn = undef;   # name of current connection
    my $skip = 0;       # 1 = skip next empty line
                        # 2 = skip current section

    my $lnum = 1;
    my $line = shift(@$data);

    LINE: while(defined($line)) {
        chomp($line);
        print STDERR sprintf("SAVE [%s:%02d]: ", $file, $lnum), " $line\n"
            if($DEBUG > 3);

        unless($sect) {

            # remember leading comments...
            if($line =~ /^\s*#/) {
                push(@scom, $line);
                $skip=0;
                $line = shift(@$data); $lnum++; next LINE;
            }
            if($line =~ /^\s*$/) {
                push(@scom, $line) unless($skip and 1 == $skip);
                $skip=0;
                $line = shift(@$data); $lnum++; next LINE;
            }

            if($line =~ /^(version|config|conn|include)([ \t]+)(.*)$/) {
                my ($type, $sep, $name, $com) = ($1, $2, $3 || '', '');
                $skip = 0;

                # check for leading comment
                if($name =~ /([ \t]+#.*)$/) {
                    $com = $1;
                    $name =~ s/[ \t]+#.*$//;
                }

                if($name !~ /^\S+$/ or ($com ne "" and $com !~ /^[ \t]+#.*/)) {
                    return ($lnum, emsg=>"syntax error '$name', '$com'",
                                   file=>$file,line=>$line);
                }

                if($type eq 'conn') {

                    # prepend version,setup,%default if needed
                    if($conf->{'version'}) {
                        push(@fout, "version ".$conf->{'version'});
                        push(@fout, "");
                        $conf->{'version'} = undef;
                    }
                    if($conf->{'setup'}) {
                        push(@fout, "config setup");
                        push(@fout, _dump_section($conf->{'setup'}));
                        push(@fout, "");
                        $conf->{'setup'} = undef;
                    }
                    if($name eq '%default') {
                        if($conf->{'conn'}->{'%default'}) {
                            push(@fout, @scom);
                            push(@fout, $line);
                            $conn = $name;
                            $sect = \%{$conf->{'conn'}->{'%default'}->{'data'}};
                        }
                    } else {
                        if($conf->{'conn'}->{'%default'}) {
                            push(@fout, 'conn %default');
                            push(@fout, _dump_section(
                                $conf->{'conn'}->{'%default'}->{'data'}
                            ));
                            push(@fout, "");
                            delete($conf->{'conn'}->{'%default'});
                        }

                        # check if conn should go into this file
                        if(exists($conf->{'conn'}->{$name}) and
                           ($conf->{'conn'}->{$name}->{'file'} eq $file) and
                           scalar(keys %{$conf->{'conn'}->{$name}->{'data'} || {}}))
                        {
                            push(@fout, @scom);
                            push(@fout, $line);
                            $conn = $name;
                            $sect = \%{$conf->{'conn'}->{$conn}->{'data'}};
                        } else {
                            # remove conn
                            $conn = $name;
                            $sect = {};
                            $skip = 2;
                        }
                    }
                }

                elsif($type eq 'config') {
                    if($name ne 'setup') {
                        return ($lnum, emsg=>"unknown '$type $name'",
                                       file=>$file,line=>$line);
                    }

                    # prepend version if needed
                    if($conf->{'version'}) {
                        push(@fout, "version ".$conf->{'version'});
                        push(@fout, "");
                        $conf->{'version'} = undef;
                    }
                    if($conf->{'setup'}) {
                        push(@fout, @scom);
                        push(@fout, $line);
                        $conn = undef;
                        $sect = \%{$conf->{'setup'}};
                    }
                }

                elsif($type eq 'include') {

                    # prepend version,setup,%default if needed
                    if($conf->{'version'}) {
                        push(@fout, "version ".$conf->{'version'});
                        push(@fout, "");
                        $conf->{'version'} = undef;
                    }
                    if($conf->{'setup'}) {
                        push(@fout, "config setup");
                        push(@fout, _dump_section($conf->{'setup'}));
                        push(@fout, "");
                        $conf->{'setup'} = undef;
                    }
                    if($conf->{'conn'}->{'%default'}) {
                        push(@fout, 'conn %default');
                        push(@fout, _dump_section(
                            $conf->{'conn'}->{'%default'}
                        ));
                        push(@fout, "");
                        delete($conf->{'conn'}->{'%default'});
                    }

                    for my $incl (@{$conf->{'include'} || []}) {
                        if( not($incl->{'done'}) and
                            $incl->{'incl'} eq $name) {
                            $incl->{'done'} = 1;
                            if($file ne $name and
                               $name ne $conf->{'file'}) {
                                push(@fout, @scom);
                                push(@fout, $line);
                            }
                            last;
                        }
                    }
                }

                elsif($type eq 'version') {
                    if($conf->{'version'}) {
                        push(@fout, @scom);
                        push(@fout, "version".$sep.$conf->{'version'}.$com);
                        $conf->{'version'} = undef;
                    }
                }

                @scom = ();
                $line = shift(@$data); $lnum++; next LINE;

            } else {
                return ($lnum, emsg=>"syntax error",
                               file=>$file,line=>$line);
            }
        } else {
            @scom = ();
            # remember section-key comments...
            if( $line =~ /^\s+#/) {
                push(@kcom, $line) unless(2 == $skip);
                $line = shift(@$data); $lnum++; next LINE;
            }

            elsif( $line =~ /^([ \t]+)(\S+?)[ \t]*=.*$/) {
                if(2 == $skip) {
                    $line = shift(@$data); $lnum++; next LINE;
                }
                my $sep = $1;
                my $key = $2;
                if(exists($sect->{$key})) {
                    my $val = $sect->{$key};
                    if($val =~ /\S+/) {
                        push(@fout, @kcom);
                        if( $val =~ /\s/) {
                            $val = '"'. $val . '"';
                        }
                        push(@fout, $sep.$key."=".$val);
                    }
                    delete($sect->{$key});
                }
                @kcom = ();
                $line = shift(@$data); $lnum++; next LINE;
            } else {
                unless(2 == $skip) {
                    push(@fout, @kcom);
                    push(@fout, _dump_section($sect));
                }
                @kcom = ();
                if($conn) {
                    delete($conf->{'conn'}->{$conn});
                } else {
                    $conf->{'setup'} = undef;
                }
                $conn = undef;
                $sect = undef;
            }
        }
    }
    if($sect) {
        if($conn) {
            delete($conf->{'conn'}->{$conn});
        }
        $conn = undef;
        $sect = undef;
    }

    # prepend version,setup,%default if needed
    if($conf->{'version'}) {
        push(@fout, @scom);
        push(@fout, "version ".$conf->{'version'});
        push(@fout, "");
        $conf->{'version'} = undef;
        @scom = ();
    }
    if($conf->{'setup'}) {
        push(@fout, @scom);
        push(@fout, "config setup");
        push(@fout, _dump_section($conf->{'setup'}));
        push(@fout, "");
        $conf->{'setup'} = undef;
        @scom = ();
    }
    if($conf->{'conn'}->{'%default'}) {
        push(@fout, @scom);
        push(@fout, "conn \%default");
        push(@fout, _dump_section(
            $conf->{'conn'}->{'%default'}->{'data'}
        ));
        push(@fout, "");
        delete($conf->{'conn'}->{'%default'});
        @scom = ();
    }

    my $eol = 0;
    if(scalar(@scom)) {
        if($scom[$#scom] eq "" or
           $scom[$#scom] =~ /^\s/) {
            $eol = 1; 
        }
        push(@fout, @scom);
        @scom = ();
    }
    # append empty line if needed
    push(@fout, "") if($eol);

    # dump all sections for this file
    for my $conn (keys %{$conf->{'conn'}}) {
        # because of recursion
        next unless exists($conf->{'conn'}->{$conn});

        if($file eq $conf->{'conn'}->{$conn}->{'file'}) {
            push(@fout, "conn $conn");
            push(@fout, _dump_section(
                $conf->{'conn'}->{$conn}->{'data'}
            ));
            push(@fout, "");
            delete($conf->{'conn'}->{$conn});
        } else {
            my $incl = $conf->{'conn'}->{$conn}->{'file'};
            next if($conf->{'file'} eq $incl);

            my ($ret, %err) = _save_ipsec_config($conf, $incl,
                                                 $save, $read);
            return ($ret, %err) if(0 != $ret);

            if(exists($conf->{'conn'}->{$conn})) {
                delete($conf->{'conn'}->{$conn});
            }
        }
    }

    # FIXME: not sufficient...:
    $eol = 0;
    for my $incl (@{$conf->{'include'} || []}) {
        if( not($incl->{'done'})) {
            push(@fout, "include $incl");
            $eol = 1;
        }
    }
    # append empty line if needed
    push(@fout, "") if($eol);

    $save->{$file} = \@fout;
    return (0);
}


#
# --------------------------------------------------------------------
#
sub _save_ipsec_secrets
{
    my $secr = shift;
    my $file = shift;
    my $save = shift;
    my $read = shift;

    unless($secr and $file and $read) {
        return (-1, emsg=>"invalid arguments");
    }

    my ($ret, $data, $err) = &$read($file);
    if( $ret) {
        return ($ret, emsg=>$data, file=>$file, erno=>$err);
    }

    sub _write_key
    {
        my $line = shift;
        my $keys = shift;
        my $file = shift;
        my $main = shift;
        my @comm = @_;
        my @data = ();

        if($line =~ /^(.*?)\s*:\s*(RSA|PSK)\s+(.*?)\s*$/i) {
            my $index = $1 || '';
            my $ktype = $2;
            my $kdata = $3;
            my $rfile = undef;
            my $rpass = undef;
            my $rdata = {};

            if(uc($ktype) eq 'RSA') {
                unless($kdata =~ /^{/) {
                    if($kdata =~ /^(\S+)\s+(.*)$/) {
                        $rfile = $1;
                        $rpass = defined($2) ? $2 : '';
                        $rpass =~ s/^\s*\"//;
                        $rpass =~ s/\"\s*$//;
                    } elsif($kdata =~ /^(\S+)$/) {
                        $rfile = $1;
                    }
                    $kdata = undef;
                } else {
                    $kdata =~ s/^{\s*//;
                    $kdata =~ s/\s*}\s*$//;
                    $kdata = "\t".$kdata;
                    my $temp = $kdata;
                    while($temp =~ s/^\s+(\S+):\s+(\S+)//) {
                        $rdata->{$1} = $2 if(defined($1));
                    }
                }
            } else {
                $kdata =~ s/^\s*\"//;
                $kdata =~ s/\"\s*$//;
            }

            my $kref = undef;
            if(uc($ktype) eq 'RSA' and $rfile) {
                #
                # check x509 files
                #
                for(my $i=0; $i<scalar(@{$keys}); $i++) {
                    $kref = $keys->[$i];
                    if($rfile eq $kref->{'x509'}) {
                        print STDERR "X509 MATCH($ktype): ",
                                     "$rfile ($index)\n"
                            if($DEBUG>2);
                        # remove kref from keys
                        splice(@{$keys}, $i, 1);
                        last;
                    }
                    $kref = undef;
                }
            } else {
                #
                # check index names
                #
                my $cidx = $index;
                if($cidx eq '' or $cidx eq '0.0.0.0') {
                   $cidx = '%any';
                }
                $cidx = '%any6' if($cidx eq '::');
                for(my $i=0; $i<scalar(@{$keys}); $i++) {
                    $kref = $keys->[$i];

                    my $kidx = $kref->{'index'};
                    if($kidx eq '' or $kidx eq '0.0.0.0') {
                       $kidx = '%any';
                    }
                    $kidx = '%any6' if($kidx eq '::');

                    if($kidx eq $cidx) {
                        print STDERR "INDEX MATCH($ktype): ",
                                     "$kidx ($index)\n"
                            if($DEBUG>2);
                        # remove kref from keys
                        splice(@{$keys}, $i, 1);
                        last;
                    }
                    $kref = undef;
                }
            }

            # simply skip (remove) if not found
            unless($kref) {
                print STDERR "REMOVE x509='", $rfile||'',
                             "', index='$index'\n"
                    if($DEBUG>2);
                return (0);
            }

            # OK, dump the key with _our_ values
            if($kref->{'type'} eq 'RSA') {
                if($kref->{'x509'}) {
                    unless(defined($kref->{'pass'})) {
                        $kref->{'pass'} = '';
                    }
                    push(@data, $index.': '.$ktype.' '.
                                $kref->{'x509'} .' "'.
                                $kref->{'pass'} .'"');
                } else {
                    my $kdata = $kref->{'data'};
                    push(@data, $index.": $ktype {");
                    while($kdata =~ s/^\s+(\S+:\s+\S+)//) {
                        push(@data, "\t".$1);
                    }
                    push(@data, "\t}");
                }
            } else {
                unless(defined($kref->{'pass'})) {
                    $kref->{'pass'} = '';
                }
                push(@data, $index.': '.$ktype.' "'.
                            $kref->{'pass'}.'"');
            }

            return (0, @comm, @data);
        }
        return (-1, emsg=>"syntax error", file=>$file,
                    line=>substr($line, 0, 20)."...");
    }

    my @fout = ();      # output data
    my @comm = ();      # comments before a key
    my $pass = 0;       # pass key leading comments
    my $prev = undef;   # remembered key lines
    my $lnum = 0;
    foreach my $line (@{$data || []}) {
        chomp($line);
        $lnum++;

        print STDERR sprintf("SAVE [%s:%02d]: ", $file, $lnum), " $line\n"
            if($DEBUG > 3);

        if($line =~ /^\s*$/ or $line =~ /^#/) {
            if($prev) {
                my ($ret, @res) = _write_key($prev, $secr->{'keys'},
                                             $file, $secr->{'file'},
                                             @comm);
                if($ret) {
                    return ($lnum-1, @res);
                }
                push(@fout, @res);
                $prev = undef;
                @comm = ();
                $pass = 1;
            }
            if($pass) {
                if($line =~ /^\s*$/) {
                    push(@comm, $line);
                    $pass = 0;
                } else {
                    push(@fout, $line);
                }
            } else {
                push(@comm, $line);
            }
            next;
        }
        $pass = 0;

        if($line =~ /^include/) {
            if($prev) {
                my ($ret, @res) = _write_key($prev, $secr->{'keys'},
                                             $file, $secr->{'file'},
                                             @comm);
                if($ret) {
                    return ($lnum-1, @res);
                }
                push(@fout, @res);
                $prev = undef;
                @comm = ();
                $pass = 1;
            }
            if($line =~ /^include[ \t]+(.*)$/) {
                my ($name, $com) = ($1, '');

                if($name =~ /([ \t]+#.*)$/) {
                    $com = $1;
                    $name =~ s/[ \t]+#.*$//;
                }
                if($name !~ /^\S+$/) {
                    return ($lnum, emsg=>"syntax error",
                                   file=>$file,line=>$line);
                }

                for my $incl (@{$secr->{'include'} || []}) {
                    if( not($incl->{'done'}) and
                        $incl->{'incl'} eq $name)
                    {
                        $incl->{'done'} = 1;
                        if($file ne $name and
                           $name ne $secr->{'file'}) {
                            push(@fout, @comm);
                            push(@fout, $line);
                        }
                        last;
                    }
                }
            } else {
                return ($lnum, emsg=>"invalid include line",
                               file=>$file, line=>$line);
            }
            @comm = ();
            next;
        }

        if($line =~ /^\S+/) {
            # line with new key
            if($prev) {
                my ($ret, @res) = _write_key($prev, $secr->{'keys'},
                                             $file, $secr->{'file'},
                                             @comm);
                if($ret) {
                    return ($lnum-1, @res);
                }
                push(@fout, @res);
                $prev = undef;
                @comm = ();
            }
            $prev = $line;
        } else {
            # continuation line
            if($prev) {
                $line =~ s/#.*$//;
                if($line !~ /^\s*$/) {
                    $prev .= $line;
                }
            } else {
                return (-1, emsg=>"syntax error",
                            line=>substr($line, 0, 20)."...");
            }
        }
    }

    push(@fout, @comm);
    @comm = ();
    if($prev) {
        my ($ret, @res) = _write_key($prev, $secr->{'keys'},
                                     $file, $secr->{'file'});
        if($ret) {
            return ($lnum-1, @res);
        }
        push(@fout, @res);
        $prev = undef;
    }

    my $eol = 0;
    for(my $i=0; $i<scalar(@{$secr->{'keys'}}); $i++) {
        my $kref = $secr->{'keys'}->[$i];
        unless($kref->{'file'}) {
            $kref->{'file'} = $secr->{'file'};
        }
        if($kref->{'file'} ne $file) {
            next if($kref->{'file'} eq $secr->{'file'});

            my ($ret, %err) = _save_ipsec_secrets($secr, $kref->{'file'},
                                                  $save, $read);
            return ($ret, %err) if(0 != $ret);
            next;
        }
        $eol = 1;
        if($kref->{'type'} eq 'RSA') {
            if($kref->{'x509'}) {
                unless(defined($kref->{'pass'})) {
                    $kref->{'pass'} = '';
                }
                push(@fout, $kref->{'index'}.': RSA '.
                            $kref->{'x509'} .' "'.
                            $kref->{'pass'} .'"');
            } else {
                my $kdata = $kref->{'data'};
                push(@fout, $kref->{'index'}.": RSA {");
                while($kdata =~ s/^\s+(\S+:\s+\S+)//) {
                    push(@fout, "\t".$1);
                }
                push(@fout, "\t}");
            }
        } else {
            unless(defined($kref->{'pass'})) {
                $kref->{'pass'} = '';
            }
            push(@fout, $kref->{'index'}.': PSK "'.
                        $kref->{'pass'}.'"');
        }
        splice(@{$secr->{'keys'}}, $i, 1);
    }
    push(@fout, "") if($eol);

    $eol = 0;
    for my $iref (@{$secr->{'include'}}) {
        unless($iref->{'file'}) {
            $iref->{'file'} = $secr->{'file'};
        }
        if($iref->{'file'} eq $file
           and not($iref->{'done'})) {
            $eol = 1;
            $iref->{'done'} = 1;
            push(@fout, "include ". $iref->{'incl'});
        }
    }
    push(@fout, "") if($eol);

    $save->{$file} = \@fout;
    return (0);
}


#
# --------------------------------------------------------------------
#
sub load_ipsec_secrets
{
    my $secr = shift;
    my $file = shift;
    my $dpth = shift;

    unless($file and $file =~ /\S+/ and -f $file) {
        return (-1, emsg=>"invalid file name",
                    file=>$file);
    }

    if(open(SECR, '<', $file)) {
        my @data = <SECR>;
        close(SECR);

        my ($ret, %err) = _load_ipsec_secrets($secr, $file,
                                              $dpth, \@data);
        return ($ret, %err) if(0 != $ret);
    } else {
        return (-2, emsg=>"can't open file",
                    file=>$file, erno=>$!);
    }
}


#
# --------------------------------------------------------------------
#
sub _load_ipsec_secrets
{
    my $secr = shift;
    my $file = shift;
    my $dpth = shift;
    my $data = shift;

    unless($secr and $file and $data) {
        return (-1, emsg=>"invalid arguments");
    }


    sub _parse_key
    {
        my $line = shift;
        my $keys = shift;
        my $file = shift;

        if($line =~ /^(.*?)\s*:\s*(RSA|PSK)\s+(.*?)\s*$/i) {
            my $index = $1 || '';
            my $ktype = $2;
            my $kdata = $3;
            my $rfile = undef;
            my $rpass = undef;
            my $rdata = {};

            if(uc($ktype) eq 'RSA') {
                unless($kdata =~ /^{/) {
                    if($kdata =~ /^(\S+)\s+(.*)$/) {
                        $rfile = $1;
                        $rpass = defined($2) ? $2 : '';
                        $rpass =~ s/^\s*\"//;
                        $rpass =~ s/\"\s*$//;
                    } elsif($kdata =~ /^(\S+)$/) {
                        $rfile = $1;
                    }
                    $kdata = undef;
                } else {
                    $kdata =~ s/^{\s*//;
                    $kdata =~ s/\s*}\s*$//;
                    $kdata = "\t".$kdata;
                    my $temp = $kdata;
                    while($temp =~ s/^\s+(\S+):\s+(\S+)//) {
                        $rdata->{$1} = $2 if(defined($1));
                    }
                }
            } else {
                $kdata =~ s/^\s*\"//;
                $kdata =~ s/\"\s*$//;
            }

            # FIXME: maybe useless => skip them?
            if(uc($ktype) eq 'RSA' and $rfile) {
                #
                # check duplicate x509 files
                #
                for my $kref (@{$keys}) {
                    next unless($kref->{'x509'});
                    if($rfile eq $kref->{'x509'}) {
                        return (-1, emsg=>"duplicate x509 key",
                                    line=>substr($line, 0, 20)."...");
                    }
                }
            } else {
                #
                # check duplicate index names
                #
                my $cidx = $index;
                if($cidx eq '' or $cidx eq '0.0.0.0') {
                   $cidx = '%any';
                }
                $cidx = '%any6' if($cidx eq '::');

                for my $kref (@{$keys}) {
                    next if($kref->{'x509'});
                    my $kidx = $kref->{'index'};
                    if($kidx eq '' or $kidx eq '0.0.0.0') {
                       $kidx = '%any';
                    }
                    $kidx = '%any6' if($kidx eq '::');

                    if($kidx eq $cidx) {
                        return (-1, emsg=>"duplicate key index",
                                    line=>substr($line, 0, 20)."...");
                    }
                }
            }

            print STDERR "ADD KEY: $ktype($index, $rfile): $kdata\n"
                if($DEBUG>2);

            if(uc($ktype) eq 'RSA') {
                return (0, (
                    'type'  => 'RSA',
                    'file'  => $file,    # source secrets file
                    'index' => $index,   # key index
                    'x509'  => $rfile,   # pem file
                    'pass'  => $rpass,   # pem passwd
                    'hash'  => $rdata,   # parsed RSA data
                    'data'  => $kdata,   # "key: val [key: val]"
                ));
            } else {
                return (0, (
                    'type'  => 'PSK',
                    'file'  => $file,    # source secrets file
                    'index' => $index,   # key index
                    'x509'  => undef,
                    'pass'  => $kdata,   # preshared key string
                    'hash'  => undef,
                    'data'  => undef,
                ));
            }
        }
        return (-1, emsg=>"syntax error",
                    line=>substr($line, 0, 20)."...");
    }

    my $lnum = 0;
    my $prev = undef;
    foreach my $line (@{$data || []}) {
        chomp($line);
        $lnum++;

        print STDERR sprintf("LOAD [%s:%02d]: ", $file, $lnum), " $line\n"
            if($DEBUG > 3);

        if($line =~ /^\s*$/ or $line =~ /^#/) {
            if($prev) {
                my ($ret, %res) = _parse_key($prev, $secr->{'keys'}, $file);
                if($ret) {
                    return ($lnum-1, file=>$file, %res);
                }
                push(@{$secr->{'keys'}}, \%res);
                $prev = undef;
            }
            next;
        }

        if($line =~ /^include/) {
            my $depth = undef;
            if(defined($dpth)) {
                if(0 >= $dpth) {
                    return (-3, emsg=>"recursion depth reached",
                                file=>$file, line=>$line);
                }
                $depth = $dpth - 1;
            }

            if($prev) {
                my ($ret, %res) = _parse_key($prev, $secr->{'keys'}, $file);
                if($ret) {
                    return ($lnum-1, file=>$file, %res);
                }
                push(@{$secr->{'keys'}}, \%res);
                $prev = undef;
            }

            if($line =~ /^include[ \t]+(\S+)[ \t]*$/) {
                my $incl = $1;
                my $full = $incl;
                my $pref = '';
                if($incl !~ /^\//) {
                    $pref = $file;
                    $pref =~ s/[^\/]+$//;
                    $full = $pref . $incl;
                }

                my @list = bsd_glob($full, GLOB_ERR | GLOB_LIMIT);
                if(0 >= scalar(@list)) {
                    return ($lnum, emsg=>"invalid include glob",
                                   file=>$file, line=>$line);
                }
                for my $name (@list) {
                    next unless($name);
                    if(($name eq $file) or ($name eq $secr->{'file'})) {
                        return ($lnum, emsg=>"recursive inclusion",
                                       file=>$file, line=>$line);
                    }

                    print STDERR "INCLUDE '$incl' => $name\n" if($DEBUG>1);

                    my ($ret, %err) = load_ipsec_secrets($secr, $name, $depth);
                    return ($ret, %err) if(0 != $ret);
                }
                push(@{$secr->{'include'}}, { 'incl' =>  $incl,
                                              'file' =>  $file,
                                              'list' => [@list] });
            } else {
                return ($lnum, emsg=>"invalid include line",
                               file=>$file, line=>$line);
            }
            next;
        }

        if($line =~ /^\S+/) {
            # line with new key
            if($prev) {
                my ($ret, %res) = _parse_key($prev, $secr->{'keys'}, $file);
                if($ret) {
                    return ($lnum-1, file=>$file, %res);
                }
                push(@{$secr->{'keys'}}, \%res);
                $prev = undef;
            }
            $prev = $line;
        } else {
            # continuation line
            if($prev) {
                $line =~ s/#.*$//;
                if($line !~ /^\s*$/) {
                    $prev .= $line;
                }
            } else {
                return (-1, emsg=>"syntax error",
                            line=>substr($line, 0, 20)."...");
            }
        }
    }
    if($prev) {
        my ($ret, %res) = _parse_key($prev, $secr->{'keys'}, $file);
        if($ret) {
            return ($lnum-1, file=>$file, %res);
        }
        push(@{$secr->{'keys'}}, \%res);
    }
    return (0);
}


#
# --------------------------------------------------------------------
#
sub _backup_and_read
{
    my $file = shift;
    my $back = shift || (($file || '') . '.old');
    my $err;

    return (-1, "invalid arguments") unless($file);
    return ( 0, [])                  unless(-e $file);

    unless(-f $file and not(-l $file)) {
        return (-1, "not a regular file");
    }
    unless(sysopen(CONF, $file, O_RDONLY)) {
        return (-2, "open error", $!);
    }

    unless(flock(CONF, LOCK_SH|LOCK_NB)) {
        $err = $!;
        close(CONF);
        return (-2, "lock error", $err);
    }

    my @stats = stat(CONF);
    if(0 == scalar(@stats)) {
        $err = $!;
        flock(CONF, LOCK_UN);
        close(CONF);
        return (-2, "stat error", $err);
    }
    my $perms = S_IMODE($stats[2]);

    unlink($back) if(-e $back);
    unless(sysopen(BACK, $back, O_RDWR|O_CREAT|O_EXCL, $perms)) {
        $err = $!;
        flock(CONF, LOCK_UN);
        close(CONF);
        return (-2, "open error", $err);
    }
    unless(flock(BACK, LOCK_EX|LOCK_NB)) {
        $err = $!;
        flock(CONF, LOCK_UN);
        close(CONF);
        close(BACK);
        return (-2, "lock error", $err);
    }

    my @data = <CONF>;
    print BACK @data;

    flock(BACK, LOCK_UN);
    close(BACK);
    flock(CONF, LOCK_UN);
    close(CONF);
    return (0, \@data); ### SUCCEED!
}

1;
__END__

=head1 NAME

    FreeSwanUtils - FreeS/WAN utilities

=head1 DESCRIPTION

    FreeSwanUtils implements an interface to load, save and
    modify FreeS/WAN configuration from L<ipsec.conf(5)> and
    the corresponding secret data from L<ipsec.secrets(5)>.

=head1 SYNOPSIS

    use FreeSwanUtils;

    my $fsu = new FreeSwanUtils(
                ipsec_root => '.' # use ./etc/ipsec.conf
              );

    $fsu->load_config() or die "load_config() ".$fsu->errstr()."\n";
    #print STDERR join("\n", $fsu->dump_config()), "\n";
    # ...
    $fsu->save_config() or die "save_config() ".$fsu->errstr()."\n";

    $fsu->load_secrets() or die "load_secrets() ".$fsu->errstr()."\n";
    #print STDERR join("\n", $fsu->dump_secrets()), "\n";
    # ...
    $fsu->save_secrets() or die "save_secrets() ".$fsu->errstr()."\n";

=head1 CONSTRUCTOR

=over 4

=item B<new( [ %args ] )>

Creates an FreeSwanUtils object with optionally different
default values:

    ipsec_version => "2.0"
        Default version string for ipsec.conf file,

    ipsec_conf    => "/etc/ipsec.conf"
        Main config file.

    ipsec_secrets => "/etc/ipsec.secrets"
        Main secrets file.

    ipsec_root    => ""
        Root directory prepended to filenames, e.q. "."
        causes reading of "./etc/ipsec.conf" instead.

=back

=head1 METHODS

=over 4

=item B<load_config( [$file] )>

Loads configuration from the main F</etc/ipsec.conf>
(or alternative file given in C<$file>) and included
files.

Returns true on success or false on error. Error info
can be fetched via C<error> and C<errstr> methods.


=item B<load_secrets( [$file] )>

Loads secrets data from the main F</etc/ipsec.secrets>
(or alternative file given in C<$file>) and included
files.

Returns true on success or false on error. Error info
can be fetched via C<error> and C<errstr> methods.


=item B<save_config( )>

Saves the configutation back to its files (incl. included).

Returns true on success or false on error. Error info
can be fetched via C<error> and C<errstr> methods.


=item B<save_secrets( )>

Saves the secrets data back to its files (incl. included).

Returns true on success or false on error. Error info
can be fetched via C<error> and C<errstr> methods.


=item B<dump_config( [$file] )>

Returns a list of lines with the content of the specified
configutation file C<$file> or the content of the main
config (the F</etc/ipsec.conf> file).


=item B<dump_secrets( [$file] )>

Returns a list of lines with the content of the specified
secrets file C<$file> or the content of the main secrets
file (the F</etc/ipsec.secrets> file).


=item B<error( [flag] )>

If C<flag> is given, returns a scalar error-value. C<flag>
can be one of the following names:

    code: negative error number or positive line number
    emsg: error message
    file: (optional) file name where the error happened
    line: (optional) line containing a syntax error
    erno: (optional) errno value

If no C<flag> given, returns C<code> in scalar context or
the complete error hash in list context.

=item B<errstr( )>

Returns and error string constructed from error info.

=back

=head1 SEE ALSO

L<ipsec.conf(5)>
L<ipsec.secrets(5)>

=head1 AUTHOR

Marius Tomaschewski, E<lt>mt@suse.deE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by SUSE LINUX AG, Nuernberg, Germany

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.

=cut
#
# vim: set ts=8 sts=4 sw=4 ai et:
#
1;
