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
our $DEBUG       = 0;
our $DEPTH       = undef;
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
    my $self;

    if($self->{'error'}->{'code'}) {
	return "ERROR[".$self->{'error'}->{'code'}."]: ".
	       $self->{'error'}->{'emsg'}.
	       ($self->{'error'}->{'file'} ? " in ".
	        $self->{'error'}->{'file'} : "").
	       ($self->{'error'}->{'erno'} ? " [errno=".
	        $self->{'error'}->{'erno'}."]" : "").
	       ($self->{'error'}->{'line'} ? " line='".
	        $self->{'error'}->{'line'}."'" : "");
		
    }    
    return "SUCCESS";
}


#
# --------------------------------------------------------------------
#
sub load_config
{
    my $self = shift;
    my $file = shift || $self->{'ipsec_root'}.
                        $self->{'ipsec_conf'};

    $self->_init_config(file => $file);

    my ($ret, %err) = load_ipsec_conf($self, $file, $DEPTH);
    if ($ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "LOAD ", $self->errstr(), "\n" if($DEBUG);
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

    my ($ret, %err) = save_ipsec_conf($self, $self->{'ipsec_version'});
    $self->_init_config();
    if( $ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "SAVE ", $self->errstr(), "\n" if($DEBUG);
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
    my $_out = shift;
    my $file = shift;

    dump_ipsec_conf($self, $_out, $file, $self->{'ipsec_version'});
}


#
# --------------------------------------------------------------------
#
sub load_secrets
{
    my $self = shift;
    my $file = shift || $self->{'ipsec_root'}.
                        $self->{'ipsec_secrets'};

    $self->_init_secrets(file => $file);

    my ($ret, %err) = load_ipsec_secrets($self, $file, $DEPTH);
    if ($ret) {
        $self->{'error'} = {code=>$ret, %err};
        print STDERR "LOAD ", $self->errstr(), "\n" if($DEBUG);
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
sub load_ipsec_secrets
{
    my $secr = shift;
    my $file = shift;
    my $dpth = shift;

    unless($file and $file =~ /\S+/ and -f $file) {
        return (-1, emsg=>"invalid file name",
                    file=>$file);
    }

    if(open(CONF, '<', $file)) {
        my @data = <CONF>;
        close(CONF);

        my ($ret, %err) = _load_ipsec_secrets($secr, $file,
                                              $dpth, \@data);
        return ($ret, %err) if(0 != $ret);
    } else {
        return (-2, emsg=>"can't open file",
                    file=>$file, erno=>$!);
    }
}

sub _load_ipsec_secrets
{
    my $secr = shift;
    my $file = shift;
    my $dpth = shift;
    my $data = shift;

    return (-1, emsg=>"not implemented");
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
    foreach (keys %conf) {
        $self->{$_} = exists($args{$_}) ?
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
    my %secr = ();
    foreach (keys %secr) {
        $self->{$_} = exists($args{$_}) ?
                      $args{$_} : $secr{$_};
    }
}

#
# --------------------------------------------------------------------
#
sub load_ipsec_conf
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

        my ($ret, %err) = _load_ipsec_conf($conf, $file,
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
sub save_ipsec_conf
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
    my ($ret, %err) = _save_ipsec_conf($conf, $file, $save,
                                       \&_backup_and_read);
    if(0 == $ret) {
        my $data = $save->{$file};

        if(scalar(@{$data || []})) {
            # included files
            for my $_file (keys %{$save}) {
                next if($file eq $_file);

                my $_data = $save->{$_file};
                if(scalar(@{$_data || []})) {
                    if(open(CONF, ">", $_file)) {
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
            if(open(CONF, ">", $file)) {
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
sub dump_ipsec_conf
{
    my $conf = shift;
    my $_out = shift;
    my $file = shift || $conf->{'file'};
    my $_ver = shift || $DEFS{'ipsec_version'};
    my $sect;
    my @temp;

    return unless($_out and $conf and $file and
                  exists($conf->{'version'}));

    if($file eq $conf->{'file'}) {
        $conf->{'version'} = $_ver unless($conf->{'version'});
 
        if($conf->{'version'}) {
            print $_out "version ", $conf->{'version'}, "\n\n";
        }

        print $_out "config setup\n";
        foreach (_dump_section($conf->{'setup'})) {
            print $_out "$_\n";
        }
        print $_out "\n";

        print $_out "conn \%default\n";
        if(exists($conf->{'conn'}->{'%default'})) {
            $sect = $conf->{'conn'}->{'%default'}->{'data'};
            foreach (_dump_section($sect)) {
                print $_out "$_\n";
            }
        }
        print $_out "\n";
    }

    for my $name (qw(block private private-or-clear
                     clear-or-private clear
                     packetdefault OEself)) {
        next unless(exists($conf->{'conn'}->{$name}));

        my $sect = $conf->{'conn'}->{$name}->{'data'} || {};
        my $curr = $conf->{'conn'}->{$name}->{'file'};
        unless($curr) {
            $curr = $file if($file eq $conf->{'file'});
        }

        if($curr eq $file and scalar(keys %{$sect})) {
            print $_out "conn $name\n";
            foreach (_dump_section($sect)) {
                print $_out "$_\n";
            }
            print $_out "\n";
        }
    }

    for my $name (keys %{$conf->{'conn'}}) {
        for my $skip (qw(%default block private private-or-clear
                      clear-or-private clear packetdefault OEself)) {
            next if($skip eq $name);
        }

        my $sect = $conf->{'conn'}->{$name}->{'data'} || {};
        my $curr = $conf->{'conn'}->{$name}->{'file'};
        unless($curr) {
            $curr = $file if($file eq $conf->{'file'});
        }

        if($curr eq $file and scalar(keys %{$sect})) {
            print $_out "conn $name\n";
            foreach (_dump_section($sect)) {
                print $_out "$_\n";
            }
            print $_out "\n";
        }
    }

    if($file eq $conf->{'file'}) {
        for my $incl (@{$conf->{'include'} || []}) {
            if($incl->{'incl'} =~ /\S+/) {
                print $_out "include ", $incl->{'incl'}, "\n";
            }
        }
    }
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
sub _load_ipsec_conf
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
            if($DEBUG > 2);

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

            if($line =~ /^version[ \t]+(\d+\.\d+)[ \t]*$/) {
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
                    return (-1, emsg=>"recursion depth reached",
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
                    return (-3, emsg=>"invalid include glob",
                                file=>$file, line=>$line);
                }
                for my $name (@list) {
                    next unless($name);
                    if(($name eq $file) or ($name eq $conf->{'file'})) {
                        return (-3, emsg=>"recursive inclusion",
                                    file=>$file, line=>$line);
                    }

                    print STDERR "INCLUDE '$incl' => $name\n" if($DEBUG);

                    my ($ret, %err) = load_ipsec_conf($conf, $name, $depth);
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
sub _save_ipsec_conf
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
    my $skip = 0;       # skip next line if empty

    my $lnum = 1;
    my $line = shift(@$data);

    LINE: while(defined($line)) {
        chomp($line);
        print STDERR sprintf("SAVE [%s:%02d]: ", $file, $lnum), " $line\n"
            if($DEBUG > 2);

        unless($sect) {

            # remember leading comments...
            if($line =~ /^\s*#/) {
                push(@scom, $line);
                $skip=0;
                $line = shift(@$data); $lnum++; next LINE;
            }
            if($line =~ /^\s*$/) {
                push(@scom, $line) unless($skip);
                $skip=0;
                $line = shift(@$data); $lnum++; next LINE;
            }
        
            if($line =~ /^(version|config|conn|include)([ \t]+)(.*)$/) {
                my ($type, $sep, $name, $com) = ($1, $2, $3 || '', '');

                # check for leading comment
                if($name =~ /([ \t]+#.*)$/) {
                    $com = $1;
                    $name =~ s/[ \t]+#.*$//;
                }

                if($name !~ /^\S+$/ or ($com ne "" and $com !~ /^[ \t]+#.*/)) {
                    return ($lnum, emsg=>"syntax error",
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

            # remember section-key comments...
            if( $line =~ /^\s+#/) {
                push(@kcom, $line);
                $line = shift(@$data); $lnum++; next LINE;
            }

            elsif( $line =~ /^([ \t]+)(\S+?)[ \t]*=.*$/) {
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
                push(@fout, @kcom);
                push(@fout, _dump_section($sect));
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
        push(@fout, _dump_section(
            $conf->{'conn'}->{'%default'}->{'data'}
        ));
        push(@fout, "");
        delete($conf->{'conn'}->{'%default'});
        @scom = ();
    }

    $skip = 0;
    if(scalar(@scom)) {
        if($scom[$#scom] eq "" or
           $scom[$#scom] =~ /^\s/) {
            $skip = 1; 
        }
        push(@fout, @scom);
        @scom = ();
    }
    # append empty line if needed
    push(@fout, "") unless($skip);

    # dump all sections for this file
    for my $conn (keys %{$conf->{'conn'}}) {
        # because of recursion
        next unless exists($conf->{'conn'}->{$conn});

        if($file eq $conf->{'conn'}->{$conn}->{'file'}) {
            push(@fout, _dump_section(
                $conf->{'conn'}->{$conn}->{'data'}
            ));
            push(@fout, "");
            delete($conf->{'conn'}->{$conn});
        } else {
            my $incl = $conf->{'conn'}->{$conn}->{'file'};
            next if($conf->{'file'} eq $incl);

            my ($ret, %err) = _save_ipsec_conf($conf, $incl,
                                               $save, $read);
            return ($ret, %err) if(0 != $ret);

            if(exists($conf->{'conn'}->{$conn})) {
                delete($conf->{'conn'}->{$conn});
            }
        }
    }

    # FIXME: not sufficient...:
    $skip = 1;
    for my $incl (@{$conf->{'include'} || []}) {
        if( not($incl->{'done'})) {
            print STDERR "FIXME: include $incl\n";
            push(@fout, "include $incl");
            $skip = 0;
        }
    }
    # append empty line if needed
    push(@fout, "") unless($skip);

    $save->{$file} = \@fout;
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
    # ...
    $fsu->save_config() or die "save_config() ".$fsu->errstr()."\n";

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

Loads configuration from the main F</etc/ipsec.conf> or
alternative file given in C<$file> and included files.

Returns true on success or false on error. Error info
can be fetched via C<error> and C<errstr> methods.


=item B<save_config( )>

Saves the configutation back to its files (incl. included).

Returns true on success or false on error. Error info
can be fetched via C<error> and C<errstr> methods.


=item B<dump_config( $out [, $file ])>

Dumps the configutation for sections matching the filename
given in C<$file> (included sections) to the handle C<$out>.

If no filename given, the content of C<$conf-E<gt>{file}>
(F</etc/ipsec.conf>) is dumped.


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
