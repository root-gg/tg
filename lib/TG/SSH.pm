#!/usr/bin/perl

use strict;
use warnings;

package TG::SSH;
require TG::BASTION;

our $debug;
our $quiet;
our $Bastion;

sub new {
    my $class  = shift;
    my $params = shift;
    my $this   = $params;

    $this->{'hostname'} = $this->{'host'}->{'hostname'};
    $this->{'port'} 	= $this->{'host'}->{'port'};
    $this->{'user'}     = $this->{'host'}->{'user'};
    $this->{'password'}	= $this->{'host'}->{'password'};
    $this->{'screen'}	= $params->{'screen'};
    $this->{'mosh'}   	= $params->{'mosh'};
    $this->{'tor'}     = $params->{'tor'};
    $this->{'bastion'}	= TG::BASTION::getBastion();		

    # If host has command we override
    $this->{'cmd'} 		= $this->{'host'}->{'exec'} if defined $this->{'host'}->{'exec'};

    # Set environnement variables to send to remote server
    $ENV{'LC_TGUSER'} = $ENV{'USER'};

    # Ask password 
    if($this->{'password'})
    {
        foreach my $i ( 1..3 )
        {
            Logger::expect("Enter " . $this->{'hostname'} . " password : ");

            my $password = TG::MISC::askPassword();

            if($password and $this->{'password'} eq $password)
            {
                Logger::debug("Password correct");
                last;
            }
            else
            {
                Logger::warn("Incorrect password !"); 
            }
        }
        continue
        {
            if($i >= 3)
            {
                Logger::warn("Max tries reached. Bye.");
                exit;
            }
        }
    }

    # Test Yubikey
    if($this->{'host'}->{'requireYubikey'})
    {
        foreach my $i ( 1..3 )
        {
            # Ask OTP
            Logger::expect("Please press Yubikey : ");
            my $otp = TG::MISC::askPassword('NONE');
            if(!$otp)
            {
                Logger::warn("No OTP detected !");
                next;
            }


            # Get Yubikey id
            my $keyId = substr($otp,0,12);
            if( ! $keyId)
            {
                Logger::warn("Invalid OTP length");
                next;
            }


            # Test if Yubikey belong to user
            if( ! grep { $_ eq $keyId } @{$this->{'bastion'}->{'yubikeys'}})
            {
                Logger::warn("This Yubikey is not attached to your bastion account !");
                next;
            }


            # Test OTP
            if(TG::MISC::isYubikeyOTPValid($otp))
            {
                # Yay, yubikey && otp are valid 
                last;
            }
            else
            {
                Logger::warn("Wrong OTP for this Yubikey. Access denied !");
                next;
            }
        }
        continue
        {
            if($i >= 3)
            {
                Logger::warn("Max tries reached. Bye.");
                exit;
            }
        }
    }


    # Test host
    if ( $this->{'hostname'} !~ /^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$/ )
    {
        Logger::warn("Invalid host specified : " . $this->{'hostname'});
        return 0;
    }

    # Get public key path
    $this->{'pubkeypath'} = '/home/' . $ENV{'USER'} . '/.ssh/id_rsa.pub';


    # Remote authorizedKeys path
    $this->{"remote_authorized_keys_path"} = '\$HOME/.ssh/authorized_keys';


    bless $this, $class;
    return $this;
}

sub getFinalCmd {
    my $this = shift;

    my $remoteServer = $this->{'hostname'};
    my $remotePort   = $this->{'port'};
    my $remoteUser   = $this->{'user'};

    my $finalCmd;
    my $begin 		= 'ssh';

    # SSH Versose ? 
    $begin 		   .= ' -v' if  $Logger::debug and $Logger::debug == 3;

    # SSH Quiet ?
    $begin 		   .= ' -q' if  $this->{'quiet'};

    # TOR
    if($this->{'tor'})
    {
        Logger::info("Using TOR Network to connect to this host...")	if ! $this->{'quiet'};
        $begin		.= " -o ConnectTimeout=10 -o ProxyCommand='nc -x localhost:9050 %h %p' ";
    }

    if ( $this->{'cmd'} ) {
        $this->{'cmd'} =~ s/^\s//;
        $this->{'cmd'} =~ s/\"/\\"/g;

        $this->{'cmd'} =~ s/ssh/ssh\ \-v/g if $Logger::debug and $Logger::debug == 3;
        $this->{'cmd'} =~ s/ssh/ssh\ \-q/g if $this->{'quiet'};

        # Complete ssh chain
        $this->{'chainItems'}   = [];

        my @ssh = split ( /(ssh|--)/ , $this->{'cmd'});
        foreach ( @ssh )
        {
            if( $_ =~ /(\S+)@(\S+)/ )
            {
                my $port    = "22";
                my $user    = $1;
                my $host    = $2;
                $host       =~ s/[^\w\-\.]//g;

                if($_ =~ /-p\s(\d+)/)
                {
                    $port = $1;
                }

                push @{$this->{'chainItems'}} , $user . '@' . $host . ':' . $port ;
            }
            elsif( $_ =~ /(\d+.\d+.\d+.\d+)/ )
            {
                push @{$this->{'chainItems'}} , $1 ; 
            }
        }

        $finalCmd = $begin . " -t -t -o SendEnv=LC_TGUSER -o ConnectTimeout=1 -p $remotePort "
        . $remoteUser . "@"
        . $remoteServer . ' -- "'
        . $this->{'cmd'} . '"';
    }
    else {
        $finalCmd = $begin . " -o SendEnv=LC_TGUSER -o ConnectTimeout=1 -p $remotePort "
        . $remoteUser . "@"
        . $remoteServer;
    }

    return $finalCmd;
}

sub connect {
    my $this = shift;

    my $remoteServer = $this->{'hostname'};
    my $remotePort   = $this->{'port'};
    my $remoteUser   = $this->{'user'};
    my $finalCmd = $this->getFinalCmd;

    # Forge Connection Chain
    if ( $ENV{SSH_CLIENT} ) {
        my ( $sshHost, $sshRemotePort, $sshLocalPort ) = split( ' ', $ENV{SSH_CLIENT} );

        my $requestIp   	= $sshHost . ":" . $sshRemotePort;
        my $localHostname   = `hostname`;
        chomp($localHostname);

        my $localString 	= $ENV{'USER'} . "@" . $localHostname ;
        my $remoteString 	= $remoteUser . '@' . $remoteServer . ":" . $remotePort;
        my $finalChain 		= [$requestIp,$localString,$remoteString];

        if($this->{'chainItems'} and scalar(@{$this->{'chainItems'}}) > 0)
        {
            foreach(@{$this->{'chainItems'}})
            {
                push @{$finalChain}, $_;
            }
        }

        my $ColoredFinalChain;
        my $i;
        for($i = 0; $i < scalar(@{$finalChain}); $i++)
        {	
            $ColoredFinalChain .= Term::ANSIColor::colored(@{$finalChain}[$i],'bright_red');
            $ColoredFinalChain .= ' ';
            $ColoredFinalChain .= Term::ANSIColor::colored('=>','magenta')		if $i < (scalar(@{$finalChain}) - 1);
            $ColoredFinalChain .= ' ' 											if $i < (scalar(@{$finalChain}) - 1);

            if($this->{'tor'} and $i == 1)
            {
                $ColoredFinalChain .= Term::ANSIColor::colored('TOR Network','bright_red');
                $ColoredFinalChain .= ' ';
                $ColoredFinalChain .= Term::ANSIColor::colored('=>','magenta')      if $i < (scalar(@{$finalChain}) - 1);
                $ColoredFinalChain .= ' '                                           if $i < (scalar(@{$finalChain}) - 1);
            }
        }

        Logger::info($ColoredFinalChain) if ! $this->{'quiet'};
    }

    Logger::debug($finalCmd);

    print "\n" if !$this->{'quiet'};

    if($ENV{'NAAB'})
    {
        system($finalCmd . ' && sleep 99999999999');
    }
    elsif($this->{'mosh'})
    {
        my $fnret = `mosh-server new -s -c 8 -l LANG=en_US.UTF-8 2>&1 -- $finalCmd`;
        if($? == 0)
        {
            my $session = $this->{'bastion'}->{'currentSession'};
            my @lines 	= split("\n", $fnret);

            foreach ( @lines )
            {	
                if( $_ =~ /^.*MOSH\sCONNECT\s(\d+)\s([^\s]+).*$/ )
                {
                    $session->{'type'} 		= 'mosh';
                    $session->{'mosh_port'} = $1;
                    $session->{'mosh_key'} 	= $2;
                    $session->{'mosh_line'}	= $_;
                }
                elsif( $_ =~ /pid\s\=\s(\d+)/ )
                {
                    $session->{'mosh_pid'}	= $1;
                }
            }

            if( $session->{'mosh_port'} && $session->{'mosh_key'} && $session->{'mosh_pid'} )
            {
                Logger::info($session->{'mosh_line'});
                $this->{'bastion'}->save;
            }
        }
        else
        {
            Logger::warn("Failed to spawn a mosh server : $fnret");
        }
        exit;
    }
    else
    {
        system($finalCmd);
    }
}

sub execCmd {
    my $this   = shift;
    my $params = shift;

    if ( $params->{'cmd'} ) {
        $this->{'cmd'} = $params->{'cmd'};
    }

    if ( $this->{'cmd'} ) {
        return $this->connect;
    }

    return 0;
}

sub addKey {
    my $this = shift;

    # Is the key already on remote host ?
    my $test =
    'ssh -q -o "BatchMode=yes" '
    . $this->{'user'} . '@'
    . $this->{'hostname'} . ' echo';
    my $fnret = `$test`;

    if ( $? eq '0' ) {
        Logger::warn("Key already on remote host !!!");
        return 1;
    }

    # Put the key
    my $cmd = 'ssh-copy-id -i \''.$this->{'pubkeypath'}.'\' -p \''. $this->{'port'}.'\' \''.$this->{'user'}.'@'.$this->{'hostname'}.'\' > /dev/null 2> /dev/null';
    $fnret = `$cmd`;

    Logger::info("Exec : $cmd") if !$this->{'quiet'};
    if ( $? eq 0 ) {
        Logger::info("Key successfully added on host !")
        if !$this->{'quiet'};
    }
    else {
        Logger::warn("ssh-copy-id failed : $fnret");
        return 0;
    }

    return 1;
}

sub removeKey {
    my $this = shift;
    my $key;

    # Get key
    my $fnret = open FILE, "<", $this->{'pubkeypath'};
    if ( !$fnret ) {
        Logger::warn("Failed to open " . $this->{'pubkeypath'} . " : $!");
        return 0;
    }
    while (<FILE>) {
        $key .= $_;
    }

    # We chomp it
    chomp($key);

    # Delete keys from remote host
    my $sed  = "sed -i '\\|$key|d' ".$this->{"remote_authorized_keys_path"};
    my $host = $this->{'hostname'};
    my $port = $this->{'port'};
    my $user = $this->{'user'};

    my $cmd = 'ssh -p '.$port.' '.$user.'@'.$host.' -t "'.$sed.'"';
    $fnret = `$cmd`;

    if ( $? eq 0 ) {
        Logger::info("Key deleted");
    }
    else {
        Logger::warn("Problem when removing key from distant host : $fnret");
        Logger::warn("Command sent : $cmd");
        return 0;
    }

    return 1;
}

sub resetHostKey {
    my $this = shift;
    my $key;
    
    use Socket;
    my ($name, $aliases, $addrtype, 
                  $length, @addrs)= gethostbyname($this->{'hostname'});
    my @hostsToCheck = map { inet_ntoa($_) } @addrs;
    push @hostsToCheck, $this->{'hostname'};
    Logger::notice("We are going to remove key for these hostname(s)/IP(s): ".join(', ',@hostsToCheck));

    foreach my $hostToCheck (@hostsToCheck)
    {
        # We test if the key is in the Known Hosts file
        my $find = 'ssh-keygen -F '.$hostToCheck.' 2>/dev/null';
        `$find`;

        if($? ne 0)
        {
            Logger::info("The key for " . $hostToCheck . " is not present in known_hosts file ");
        }
        else 
        {
            # We delete it
            my $remove  = 'ssh-keygen -R '.$hostToCheck.' 2>/dev/null';
            `$remove`;

            if ( $? eq 0 ) 
            {
                Logger::info("The ssh key for " . $hostToCheck . " has been removed");
            }
            else
            {
                Logger::warn("Problem when removing " . $hostToCheck . " host key");
            }
        }
    }
}

1;

