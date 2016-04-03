#!/usr/bin/perl

use strict;
use warnings;

use JSON::XS;
use TG::MISC;
use TG::HOST;

package TG::BASTION;

our $Bastion;

sub getBastion
{
    return $Bastion;
}

sub new
{
    my $class 	= shift;
    my $params  = shift;

    # Singleton pattern
    if($Bastion)
    {
        return $Bastion;
    }


    # Remeber granted state
    my $granted = 0;


    # Detect username
    my $username = $ENV{'USER'};
    $username	 = $ENV{'REMOTE_USER'} if $ENV{'REMOTE_USER'};


    # Init Object Configuration
    my $this =
    {
        'tunnelCreated'	=> 0,
        'path'			=> $ENV{'HOME'}.'/.tg.hosts.bin',
        'store'			=> {},
        'allowed_ips' 	=> [],
        'sessions'     	=> [],
        'yubikeys'		=> [],
        'settings'		=>
        {
            'default_user' => $username,
        },
    };


    # Bless
    bless $this, $class;


    # Loading conf
    $this->load();


    # Yubikey check
    if( scalar(@{$this->{'yubikeys'}}) > 10 )
    {
        Logger::info("The command line is : " . $params->{'commandLine'});
        Logger::expect("Please provide Yubikey OTP : ");
        system('stty','-echo');
        chop(my $otp=<STDIN>);
        system('stty','echo');
        print "\n";

        my $keyId = substr($otp,0,12);
        if($keyId && grep { $_ eq $keyId } @{$this->{'yubikeys'}})
        {
            if(TG::MISC::isYubikeyOTPValid($otp))
            {
                Logger::info("Access granted :)");
                $granted = 1;
            }
            else
            {
                Logger::crit("Not a valid OTP for your key");
            }
        }
        else
        {
            Logger::warn("This yubikey is not in your profile...");
        }
    }


    # Ask password
    if(!$granted && $this->{'settings'}->{'default_password'} and $ENV{'SSH_CLIENT'})
    {
        for my $i ( 1 .. 3 )
        {
            Logger::expect("Please enter master password : ");

            my $password = TG::MISC::askPassword();

            if($password && $password eq $this->{'settings'}->{'default_password'})
            {
                $granted = 1;
                Logger::info("Password correct");
                last;
            }
            else
            {
                Logger::warn("Invalid master password !");
            }
        }
    }
    if(!$this->{'settings'}->{'default_password'})
    {
        $granted = 1;
    }

    # Are we granted ?
    if( !$granted )
    {
        Logger::crit("No auth method succeeded to allow your access. Bye !");
        exit;
    }


    # Clean old Sessions
    $this->cleanOldSessions();

    # Ssh client infos
    if($ENV{SSH_CLIENT})
    {
        my @infos				= split( ' ', $ENV{SSH_CLIENT} );
        $this->{'clientIp'}	 	= $infos[0];
        $this->{'clientPort'}   = $infos[1];
        $this->{'localPort'}    = $infos[2];

        # Check ip
        if( ! grep { $_ eq $this->{'clientIp'} } @{$this->{'allowed_ips'}} )
        {
            Logger::debug("IP " . $this->{'clientIp'} . " unknown !");

            if($this->{'settings'}->{'phone'} or $this->{'settings'}->{'email'} or $this->{'settings'}->{'authenticator'})
            {
                my $fnret = $this->generateSendAndPromptCode;
            }
            else
            {
                Logger::debug("Phone or Email not set, we do not verify " . $this->{'clientIp'});
                Logger::debug("To verify this ip please set a phone number or email address : ");
                Logger::debug("     -> tg -sn 06xxxxxxxx");
                Logger::debug("     -> tg -se you\@domain.tld");
            }
        }
    }


    # Check if private key is here
    if( ! -e $ENV{'HOME'} . "/.ssh/id_rsa" )
    {
        Logger::info("Private key not found..");
        Logger::info("Generating one...");

        my $fnret = `ssh-keygen -q -t rsa -f ~/.ssh/id_rsa -N ""`;

        if($? == 0)
        {
            Logger::info("Done !");
        }
        else
        {
            Logger::warn("Failed to create your private key : $fnret -- $!");
        }
    }


    # Check panic
    if( $params and $params->{'reset'} )
    {
        Logger::crit("Reset Detected !!!");
        Logger::crit("Removing configuration from bastion...");

        $this->{'settings'} = {};
        $this->{'store'}    = {};
        $this->save();
    }



    # Get tty
    my $tty     = $ENV{'SSH_TTY'} || 'NoTTY';
    $tty        =~ s/\/dev\///;
    Logger::debug("Your local tty is : $tty");
    Logger::debug("Current pid is    : $$");

    # Is panic
    if($params->{'reset'})
    {
        Logger::crit("Killing Process of user...");

        my $fnret = `ps aux | grep $< | grep -v root | grep -v $$ | grep -v "$tty" | awk {'print \$2'}`;
        my @pids  = split("\n", $fnret);
        foreach(@pids)
        {
            my $fnret = TG::MISC::killPid($_);
        }
    }

    # Detect tunnels
    if($ENV{'SSH_CLIENT'})
    {
        my $tunnels     	= `netstat -tanue | grep LISTEN | grep -v tcp6 | grep $< | awk {' print \$4'}`;
        my $tunnelsDetected = {};
        if($? eq 0)
        {
            my @lines = split('\n',$tunnels);
            foreach(@lines)
            {
                if( $_ =~ /^(.*):(\d+)$/)
                {
                    my $Sessions = [ grep { ($_->{'tunnel'} || '') eq $2 } @{$this->{'sessions'}} ] ;

                    if( scalar(@$Sessions) == 0 )
                    {
                        Logger::notice("Tunnel created on port : $2");
                        $this->{'tunnelCreated'}++;
                        $this->{'currentSession'}->{'tunnel'} = $2;
                    }
                }
            }
        }
    }


    # Launch agent
    my $SSH_AUTH_SOCK;
    my $SSH_AGENT_PID;

    # Launch Agent and get variables
    my $fnret = `ssh-agent`;

    if($? == 0)
    {
        my @lines = split("\n", $fnret);

        foreach (@lines)
        {
            $SSH_AUTH_SOCK = $1 if $_ =~ /SSH_AUTH_SOCK=([^;]+)/ ;
            $SSH_AGENT_PID = $1 if $_ =~ /SSH_AGENT_PID=([^;]+)/ ;
        }

        if($SSH_AUTH_SOCK and $SSH_AGENT_PID)
        {
            Logger::debug("SSH AGENT SOCK : $SSH_AUTH_SOCK ");
            Logger::debug("SSH AGENT PID  : $SSH_AGENT_PID ");
            Logger::debug("Adding your key to agent...");

            $ENV{'SSH_AUTH_SOCK'} 					= $SSH_AUTH_SOCK;
            $ENV{'SSH_AGENT_PID'} 					= $SSH_AGENT_PID;
            $this->{'currentSession'}->{'agent'} 	= $SSH_AGENT_PID;

            system('ssh-add > /dev/null 2> /dev/null');
        }
        else
        {
            Logger::warn("Failed to get SSH Agent parameters");
        }
    }
    else
    {
        Logger::warn("Failed to launch SSH Agent : $fnret");
    }


    # Set session
    if($ENV{'SSH_CLIENT'})
    {
        $this->{'currentSession'}->{'pid'} 			= $$,
        $this->{'currentSession'}->{'tty'} 			= $tty;
        $this->{'currentSession'}->{'clientIp'} 	= $this->{'clientIp'};
        $this->{'currentSession'}->{'clientPort'} 	= $this->{'clientPort'};
        $this->{'currentSession'}->{'commandLine'} 	= $params->{'commandLine'};

        # Save session
        Logger::debug("Saving session..");
        push @{ $this->{'sessions'} } , $this->{'currentSession'};
        $this->save;
    }


    # List screens
    $this->{'screens'} = TG::MISC::listScreens();


    $Bastion = $this;
    return $Bastion;
}

sub cleanOldSessions
{
    my $this 	 	= shift;
    my $params	 	= shift;
    my $killMyself	= $params->{'killMyself'};

    Logger::debug("Cleaning old and dead sessions...");

    for( my $i = 0; $i < scalar(@{$this->{'sessions'}}); $i++ )
    {
        my $session	= @{$this->{'sessions'}}[$i];
        my $pid 	= $session->{'pid'} or next;
        my $agent   = $session->{'agent'};
        my $type	= $session->{'type'};

        Logger::debug("Session $pid : ");

        # Kill agent
        if($agent and TG::MISC::isPidAlive($agent))
        {
            my $fnret = TG::MISC::killPid($agent);

            if( $fnret )
            {
                Logger::debug("---> Cleaned agent $agent");
            }
            else
            {
                Logger::warn("Failed to kill previous ssh agent with pid $agent");
            }
        }

        # Clean session if pid is not alive anymore
        if( $type && $type eq 'mosh' )
        {
            my $moshpid = $session->{'mosh_pid'};
            if( $moshpid && ! TG::MISC::isPidAlive( $moshpid ))
            {
                Logger::debug("---> Cleaned MOSH session");
                splice @{$this->{'sessions'}}, $i, 1;
                $this->save;
                next;
            }
        }
        else
        {
            if( ! TG::MISC::isPidAlive($pid))
            {
                Logger::debug("---> Cleaned session");
                splice @{$this->{'sessions'}}, $i, 1;
                $this->save;
                next;
            }
            elsif( $killMyself and $pid == $$ )
            {
                Logger::debug("---> Clean myself (we are in END block)");
                splice @{$this->{'sessions'}}, $i, 1;
                $this->save;
                next;
            }
        }
        Logger::debug("---> Nothing to do.");
    }

    return 1;
}

sub generateSendAndPromptCode
{
    my $this = shift;

    if( ! $this->{'settings'}->{'phone'} and ! $this->{'settings'}->{'email'} and ! $this->{'settings'}->{'authenticator'} )
    {
        return 1;
    }


    # Generate code
    my $code = int(rand(8999)) + 1000;


    # Display
    Logger::info("We are sending a code to authentificate you.");
    Logger::info("We send it to the following address/phone :");

    # Send mail
    if( $this->{'settings'}->{'email'} )
    {
        my $localHostname = `hostname`;
        chomp($localHostname);

        use Email::MIME;
        use Email::Sender::Simple qw(sendmail);

        Logger::info("      -> Mail : " . colored($this->{'settings'}->{'email'},'magenta'));

        my $mail = Email::MIME->create(
            header_str => [
                From    => 'bastion@'.$localHostname,
                To      =>  $this->{'settings'}->{'email'},
                Subject => '[BASTION-SSH] Your code : ' . $code,
            ],
            attributes => {
                encoding => 'quoted-printable',
                charset  => 'ISO-8859-1',
            },
            body_str => "The code for your demand is : $code\n",
        );

        my $fnret = sendmail($mail);
    }

    if( $this->{'settings'}->{'authenticator'} )
    {
        Logger::info("      -> One Time Password " . colored('authenticator','magenta'));
    }

    # Send sms code
    if( $this->{'settings'}->{'phone'} )
    {
        use LWP::Simple;

        Logger::info("      -> Sms  : " . colored($this->{'settings'}->{'phone'},'magenta'));

        my $message = "Code for SSH Bastion : " . $code;
        my $dest	= $this->{'settings'}->{'phone'};
        my $content = get("https://sms.root.gg/?message=$message&to=$dest");
    }

    # Prompt
    print "\n";
    Logger::expect("Please type the code you received : ");

    my $input = <STDIN>;
    chomp($input);

    my $codeIsValid = 0;
    if($code eq $input)
    {
        $codeIsValid = 1;
    }

    if($this->{'settings'}->{'authenticator'})
    {
        use Authen::OATH;
        use Convert::Base32;
        my $oath = Authen::OATH->new();
        my $otp = $oath->totp(decode_base32($this->{'settings'}->{'authenticator'}));
        if($otp eq $input)
        {
            $codeIsValid = 1;
        }
    }

    if($codeIsValid)
    {
        Logger::info("Correct code");

        push @{$this->{'allowed_ips'}} , $this->{'clientIp'};
        $this->save;
    }
    else
    {
        Logger::warn("Invalid code, please try again !");
        exit;
    }


    return 1;
}


sub setPhone
{
    my $this 	= shift;
    my $number 	= shift;


    if($number =~ /^(00|\+)?\d+$/)
    {
        $this->{'settings'}->{'phone'} = $number;
        $this->save;
        Logger::info("Phone number set to : " . $this->{'settings'}->{'phone'});
        return 1;
    }
    else
    {
        Logger::warn("Invalid phone number : $number !");
        return 0;
    }
}

sub deletePhone
{
    my $this 	= shift;

    if( defined $this->{'settings'}->{'phone'})
    {
        delete $this->{'settings'}->{'phone'};
        $this->save;
        Logger::info("Phone number deleted");
    }
    else
    {
        Logger::warn("No phone number set !");
    }
}


sub setAuthenticator
{
    my $this    = shift;

    use Authen::OATH;
    use Convert::Base32;
    # Prompt
    my @set = ('0' ..'9', 'A' .. 'F');
    my $randomKey = join '' => map $set[rand @set], 1 .. 10;

    my $otpKey = uc(encode_base32($randomKey));
    Logger::expect("Please add this code to your OTP application : $otpKey");
    print "\n";
    Logger::expect("Then, please type the code generated by the application : ");

    my $input = <STDIN>;
    chomp($input);

    my $oath = Authen::OATH->new();
    my $otp = $oath->totp(decode_base32($otpKey));
    if($otp eq $input)
    {
        $this->{'settings'}->{'authenticator'} = $otpKey;
        $this->save;

        Logger::info("Authenticator OTP Key set to : " . $this->{'settings'}->{'authenticator'});
        return 1;
    }

    Logger::warn("Invalid OTP code");

    return 0;
}

sub deleteAuthenticator
{
    my $this    = shift;

    if( defined $this->{'settings'}->{'authenticator'})
    {
        delete $this->{'settings'}->{'authenticator'};
        $this->save;

        Logger::info("Authenticator OTP deleted");
        return 1;
    }
    else
    {
        Logger::warn("No authenticator set !");
    }

    return 0;
}

sub setEmail
{
    my $this    = shift;
    my $email   = shift;

    if ( $email and $email =~ /[\w\-]+(\.[\w\-]+)*@[\w\-]+(\.[\w\-]+)*\.\w+/ )
    {
        $this->{'settings'}->{'email'} = $email;
        $this->save;

        Logger::info("Email address set to : " . $this->{'settings'}->{'email'});
        return 1;
    }
    else
    {
        Logger::warn("Not valid email address : $email");
    }

    return 0;
}

sub deleteEmail
{
    my $this    = shift;

    if( defined $this->{'settings'}->{'email'})
    {
        delete $this->{'settings'}->{'email'};
        $this->save;

        Logger::info("Email address deleted");
        return 1;
    }
    else
    {
        Logger::warn("No email set !");
    }

    return 0;
}


sub getHostByAlias
{
    my $this = shift;
    my $alias = shift;
    my ($host,$hostname,$command);

    return undef unless $alias;

    Logger::debug2("Alias passed to getHostByAlias : $alias");
    Logger::debug3("Dumper of Store : " . Data::Dumper::Dumper($this->{'store'}));

    if( $this->{'store'}->{$alias} )
    {
        $host = $this->{'store'}->{$alias}
    }
    else
    {
        map { if ( grep { $_ eq $alias } @{$this->{'store'}->{$_}->{'aliases'}} ) { $hostname = $_  } } keys %{$this->{'store'}} ;
        map { if ( grep { $_ eq $alias } keys %{$this->{'store'}->{$_}->{'cmds'}} ) { $hostname = $_ ; $command = $this->{'store'}->{$_}->{'cmds'}->{$alias}  } } keys %{$this->{'store'}} ;

        if ( $hostname and $this->{'store'}->{$hostname} )
        {
            $this->{'store'}->{$hostname}->{'exec'} = $command;
            $host = $this->{'store'}->{$hostname};
        }
        else
        {
            $host = new TG::HOST({ hostname => $alias , exec => $command });
        }
    }

    Logger::debug("getHostByAlias return this host : " . Data::Dumper::Dumper($host));
    return $host;
}

sub checkAlias
{
    my $this  = shift;
    my $alias = shift;

    foreach my $hostname ( keys %{ $this->{'store'} } )
    {
        if ( $alias eq $hostname or grep /^$alias$/, @{ $this->{'store'}->{$hostname}->{'aliases'} } or grep /^$alias$/, keys %{ $this->{'store'}->{$hostname}->{'cmds'} } )
        {
            Logger::warn("Alias $alias already exists");
            exit 1;
        }
    }
}

sub add
{
    my $this = shift;
    my $host = shift;

    unless ( $host and ref $host eq 'TG::HOST' )
    {
        Logger::warn("No host found");
    }

    if( not defined $this->{'store'}->{$host->{'hostname'}})
    {
        Logger::info("Host " . $host->{'hostname'} . " created");
    }

    $this->{'store'}->{$host->{'hostname'}} = $host;
    $this->save;
}


sub addYubikey
{
    my $this 	= shift;
    my $otp  	= shift;
    my $keyId 	= substr($otp, 0, 12);


    if( grep { $_ eq $keyId } @{$this->{'yubikeys'}} )
    {
        Logger::warn("Your key is already present in your profile");
    }
    else
    {
        Logger::info("Key $keyId successfully added");
        push @{$this->{'yubikeys'}}, $keyId;
        $this->save;
    }
}

sub remove
{
    my $this = shift;
    my $host = shift;

    unless ( $host and ref $host eq 'TG::HOST' )
    {
        Logger::warn("No host found");
    }

    unless( $this->{'store'}->{$host->{'hostname'}} )
    {
        Logger::warn("Host ".$host->{'hostname'}." does not exist");
        return 0;
    }

    delete $this->{'store'}->{$host->{'hostname'}};


    Logger::info("Host " . $host->{'hostname'} . " deleted");
    $this->save;
}

sub removeYubikey
{
    my $this    = shift;
    my $otp     = shift;
    my $keyId   = substr($otp, 0, 12);


    for ( my $i = 0 ; $i < scalar(@{$this->{'yubikeys'}}) ; $i++)
    {
        if( @{$this->{'yubikeys'}}[$i] eq $keyId)
        {
            Logger::info("Key $keyId successfully removed");
            splice( @{$this->{'yubikeys'}} , $i , 1 );
            $this->save;
            return;
        }
    }

    Logger::warn("Key $keyId not found in your configuration");
    return;
}

sub setPassword
{
    my $this = shift;
    my $password;

    Logger::expect("Please enter password : ");
    system('stty','-echo') ;
    chop($password=<STDIN>);
    system('stty', 'echo');
    print "\n";

    if ( $password )
    {
        require Digest;
        my $sha1 = Digest->new("SHA-1");
        $sha1->add($password);
        $this->{'settings'}->{'default_password'} = $sha1->hexdigest;
    }
    else
    {
        $this->{'settings'}->{'default_password'} = undef;
    }

    $this->save;
}

sub load
{
    my $this = shift;
    my $json;
    my $struct;

    return 0 if( ! -e  $this->{'path'});

    if( open FILE, "<", $this->{'path'} )
    {
        while(<FILE>)
        {
            $json .= $_;
        }
        close FILE;
    }
    else
    {
        Logger::warn("Can't open ".$this->{'path'}." to load data : $!");
    }

    if($json)
    {
        $struct = JSON::XS::decode_json($json);
    }
    else
    {
        $struct = {};
    }

    if($struct->{'settings'})
    {
        $this->{'settings'} = $struct->{'settings'};
    }

    if($struct->{'sessions'})
    {
        $this->{'sessions'} = $struct->{'sessions'};
    }

    if($struct->{'allowed_ips'})
    {
        $this->{'allowed_ips'} = $struct->{'allowed_ips'};
    }

    if($struct->{'yubikeys'})
    {
        $this->{'yubikeys'} = $struct->{'yubikeys'};
    }


    if ( $struct->{'hosts'} )
    {
        foreach my $hostname ( keys %{$struct->{'hosts'}} )
        {
            my $host = new TG::HOST( $struct->{'hosts'}->{$hostname} );
            $this->{'store'}->{$hostname} = $host;
        }
    }

    return 0;
}

sub save
{
    my $this = shift;

    my $struct = {
        'settings'  	=> $this->{'settings'},
        'hosts'     	=> {},
        'allowed_ips' 	=> [],
        'sessions'		=> [],
    };

    foreach my $hostname ( keys %{$this->{'store'}} )
    {
        $struct->{'hosts'}->{$hostname} = {};
        foreach my $key ( qw/hostname port user aliases password cmds requireYubikey/ )
        {
            $struct->{'hosts'}->{$hostname}->{$key} = $this->{'store'}->{$hostname}->{$key};
        }
    }

    foreach my $ip ( @{$this->{'allowed_ips'}} )
    {
        push @{$struct->{'allowed_ips'}}, $ip;
    }

    foreach my $session ( @{ $this->{'sessions'} } )
    {
        push @{$struct->{'sessions'}}, $session;
    }

    if( $this->{'yubikeys'} )
    {
        $struct->{'yubikeys'} = $this->{'yubikeys'};
    }

    my $xs = JSON::XS->new();
    $xs->pretty(1);
    my $json = $xs->encode($struct);


    if( open FILE, ">", $this->{'path'} )
    {
        print FILE $json;
        close FILE;
    }
    else
    {
        Logger::warn("Can't open ".$this->{'path'}." to save data : $!");
    }

    return 1;
}

sub printDetail
{
    my $hosts = shift;

    Logger::debug2(Data::Dumper::Dumper($hosts));

    use Term::ANSIColor qw(:constants colored);

    if(scalar(keys %{$hosts->{'store'}} > 0))
    {
        print GREEN "-----------------------------------------------------------------\n";
        print GREEN " TG SSH Bastion - Access List - " . scalar(keys %{$hosts->{'store'}}) .  "\n";
        print GREEN "-----------------------------------------------------------------\n";
        print RESET;
        my $hostColumnSize = 0;
        my $userColumnSize = 0;
        my $portColumnSize = 0;
        foreach my $hostname ( sort keys %{ $hosts->{'store'} } )
        {
            my $host = $hosts->{'store'}->{$hostname};
            my $user = $host->{'user'} || $hosts->{'settings'}->{'default_user'};
            my $port = $host->{'port'} || 22;
            
            my $hostLength = length $hostname;
            if($hostLength > $hostColumnSize)
            {
                $hostColumnSize = $hostLength;
            }
            my $userLength = length $user;
            if($userLength > $userColumnSize)
            {
                $userColumnSize = $userLength;
            }
            my $portLength = length $port;
            if($portLength > $portColumnSize)
            {
                $portColumnSize = $portLength;
            }
        }

        foreach my $hostname ( sort keys %{ $hosts->{'store'} } )
        {
            my $host = $hosts->{'store'}->{$hostname};
            my $user = $host->{'user'} || $hosts->{'settings'}->{'default_user'};
            my $port = $host->{'port'} || 22;
            my $aliases = '';
            map { $aliases .= colored ($_,'magenta') . ", " } @{ $host->{'aliases'} };
            $aliases =~ s/\,\s$//;
            my $password = ($host->{'password'}) ? 'X' : '-';

            printf "%-".$hostColumnSize."s   user : %-".$userColumnSize."s   pass : %-1s   port : %-".$portColumnSize."s   aliases : %-50s \n", $hostname, $user, $password, $port, $aliases;
        }
        print "\n\n";
    }

    # List commands of all hosts
    my $CommandsAliases;
    foreach my $hostname ( sort keys %{ $hosts->{'store'} } )
    {
        if($hosts->{'store'}->{$hostname}->{'cmds'})
        {
            foreach my $alias ( keys %{$hosts->{'store'}->{$hostname}->{'cmds'}} )
            {
                my $cmd = $hosts->{'store'}->{$hostname}->{'cmds'}->{$alias};
                my $hash =
                {
                    cmd 	=> $cmd,
                    alias 	=> $alias,
                    host	=> $hostname,
                };
                $CommandsAliases->{$alias} = $hash;
            }
        }
    }

    if(scalar(keys %$CommandsAliases) > 0)
    {
        print GREEN "-----------------------------------------------------------------\n";
        print GREEN " TG SSH Bastion - Command Aliases List - " . scalar(keys %$CommandsAliases)  . "\n";
        print GREEN "-----------------------------------------------------------------\n";
        print RESET;

        my $aliasColumnSize = 0;
        my $hostColumnSize = 0;
        foreach my $alias (sort keys %$CommandsAliases)
        {
            my $hostname	= $CommandsAliases->{$alias}->{'host'};
            my $host        = $hosts->{'store'}->{$hostname};
            my $hostOfAlias = $host->{'hostname'};
            if($host->{'aliases'}[0])
            {
                $hostOfAlias = $host->{'aliases'}[0];
            }
            my $aliasLength = length $alias;
            if($aliasLength > $aliasColumnSize)
            {
                $aliasColumnSize = $aliasLength;
            }
            my $hostLength = length $hostOfAlias;
            if($hostLength > $hostColumnSize)
            {
                $hostColumnSize = $hostLength;
            }
        }
        
        foreach my $alias (sort keys %$CommandsAliases)
        {
            my $hostname	= $CommandsAliases->{$alias}->{'host'};
            my $host        = $hosts->{'store'}->{$hostname};
            my $command     = $host->{'cmds'}->{$alias};
            my $hostOfAlias = $host->{'hostname'};
            if($host->{'aliases'}[0])
            {
                $hostOfAlias = $host->{'aliases'}[0];
            }

            printf "%-".$aliasColumnSize."s   host : %-".$hostColumnSize."s   command : %-100s \n", $alias, $hostOfAlias, $command;
        }

        print "\n\n";
    }

    if(scalar(@{ $hosts->{'sessions'} }) > 0)
    {
        print GREEN "-----------------------------------------------------------------\n";
        print GREEN " TG SSH Bastion - Sessions List - " . scalar(@{ $hosts->{'sessions'} })  . "\n";
        print GREEN "-----------------------------------------------------------------\n";
        print RESET;

        my $clientColumnSize = 0;
        my $pidColumnSize = 0;

        foreach my $Session (@{ $hosts->{'sessions'} })
        {
            my $client      = $Session->{'clientIp'} . ':' . $Session->{'clientPort'};
            my $pid 		= $Session->{'pid'};

            my $clientLength = length $client;
            if($clientLength > $clientColumnSize)
            {
                $clientColumnSize = $clientLength;
            }

            my $pidLength = length $pid;
            if($pidLength > $pidColumnSize)
            {
                $pidColumnSize = $pidLength;
            }
        }

        foreach my $Session (@{ $hosts->{'sessions'} })
        {
            my $client      = $Session->{'clientIp'} . ':' . $Session->{'clientPort'};
            my $pid 		= $Session->{'pid'};
            my $command     = $Session->{'commandLine'};
            my $type        = 'command';
            if($Session->{'tunnel'})
            {
                $type       = 'tunnel';
                $command    = colored($Session->{'tunnel'},'magenta');
            }

            if($$ eq $Session->{'pid'})
            {
                $command   .= colored(' (current)', 'blue');
            }

            printf "%-".$clientColumnSize."s   pid : %-".$pidColumnSize."s  ".$type." : %-100s \n", $client, $pid , $command;
        }

        print "\n";
    }


    if(scalar(@{$hosts->{'screens'}} > 0))
    {
        print GREEN "-----------------------------------------------------------------\n";
        print GREEN " TG SSH Bastion - Screens List \n";
        print GREEN "-----------------------------------------------------------------\n";
        print RESET;
        foreach my $screen ( @{ $hosts->{'screens'} } )
        {
            my $name 	= $screen->{'name'};
            my $pid 	= 'pid : ' 		. $screen->{'pid'};
            my $creation= 'creation : ' . $screen->{'creation'};
            my $status  = 'status : '	. $screen->{'status'};

            printf "%-23s %-20s %-35s %-12s \n", $name, $pid, $creation, $status;
        }
        print "\n";
    }

    return 1;
}


1;
