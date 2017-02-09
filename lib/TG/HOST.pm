#!/usr/bin/perl

use strict;
use warnings;

use JSON::XS;
use TG::MISC;

package TG::HOST;

sub new
{
    my $class   = shift;
    my $params  = shift;
    my $this	= $params;

    bless $this, $class;	
    $this->init;
    return $this;
}

sub init
{
    my $this = shift;
    $this->{'aliases'} 	||= [];
    $this->{'cmds'}		||= {};
}

sub addAlias
{
    my $this 	= shift;
    my $alias 	= shift;

    return 0 unless $alias;

    unless( grep /^$alias$/, @{$this->{'aliases'}})
    {
        push @{$this->{'aliases'}}, $alias;
        Logger::info("Adding alias $alias => ". $this->{'hostname'});
    }
    else
    {
        Logger::warn("Alias $alias already exists");
    }
}

sub removeAlias
{
    my $this 	= shift;
    my $alias 	= shift;

    if(grep /^$alias$/, @{$this->{'aliases'}})
    {
        $this->{'aliases'} = [ grep !/$alias/, @{$this->{'aliases'}} ]; # <== ANOTHER MASTERPIECE FROM SKATKATT
        Logger::info("Alias $alias for host ".$this->{'hostname'}." has been removed");
    }
    else
    {
        Logger::warn("Alias $alias not found");
        return 0;
    }

    return 1;
}

sub isAlias
{
    my $this    = shift;
    my $alias   = shift;

    if(grep /^$alias$/, @{$this->{'aliases'}})
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

sub addCmd
{
    my $this 	= shift;
    my $params 	= shift;

    my $alias 	= $params->{'alias'};
    my $cmd		= $params->{'cmd'};

    return 0 if not $alias;
    return 0 if not $cmd;

    my $hash 	= { $alias => $cmd };

    if(grep /^$alias$/, keys %{$this->{'cmds'}})
    {
        Logger::warn("Alias $alias already exist !");
        return 0;
    }
    else
    {
        $cmd =~ s/^\s+//;
        $this->{'cmds'}->{$alias} = $cmd;
        Logger::info("Command alias $alias successfully added for host " . $this->{'hostname'});
    }

    return 1;
}

sub removeCmd
{
    my $this 	= shift;
    my $alias   = shift;

    return 0 if not $alias;

    if(grep /^$alias$/, keys %{$this->{'cmds'}}) 
    {
        delete $this->{'cmds'}->{$alias};
        Logger::info("Command alias $alias for host " . $this->{'hostname'} . " has been removed");
    }
    else
    {
        Logger::warn("Command alias $alias not found");
        return 0;
    }


}


sub enableYubikey
{
    my $this    = shift;

    if($this->{'requireYubikey'})
    {
        Logger::info("Yubikey already enabled on " . $this->{'hostname'});
        return;
    }

    Logger::info("Yubikey enabled on " . $this->{'hostname'});
    $this->{'requireYubikey'} = 1;

    return;
}


sub disableYubikey
{
    my $this    = shift;

    if( ! $this->{'requireYubikey'})
    {
        Logger::info("Yubikey already disabled on " . $this->{'hostname'});
        return;
    }

    # Ask user to input otp to disable
    Logger::expect("Please press your Yubikey to disable : ");
    my $otp = TG::MISC::askPassword('NONE');
    if($otp)
    {
        if(TG::MISC::isYubikeyOTPValid($otp))
        {
            Logger::info("Yubikey disabled on " . $this->{'hostname'});
            $this->{'requireYubikey'} = 0;

            return 1;
        }
        else
        {
            Logger::warn("Invalid OTP");
            return 0;
        }
    }
    else
    {
        Logger::warn("Invalid OTP");
        return 0;
    }

    return 0;
}


sub isCmd
{
    my $this    = shift;
    my $cmd     = shift;

    if(grep /^$cmd$/, keys %{$this->{'cmds'}})
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

sub setPassword
{
    my $this = shift;
    my $password;

    Logger::expect("Please set a pass for " . $this->{'hostname'} . " : ");
    $this->{'password'} = TG::MISC::askPassword();
}

1;

