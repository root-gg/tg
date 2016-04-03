#!/usr/bin/perl

use strict;
use warnings;

package TG::MISC;


sub askPassword 
{
    my $method = shift || 'SHA1';

    system('stty','-echo');
    chop(my $password=<STDIN>);
    system('stty','echo');

    print "\n";

    # Test empty 
    return undef if ! $password;

    if($method eq 'SHA1')
    {
        # Get Hash
        require Digest;
        my $sha1 = Digest->new("SHA-1");
        $sha1->add($password);
        $password = $sha1->hexdigest;
    }
    elsif($method eq 'CRYPT')
    {
        $password = crypt($password,$password);
    }

    return $password;
}

sub isPidAlive
{
    my $pid		= shift;

    if( $pid =~ /^\d+$/)
    {
        my $fnret = `ps -p $pid`;
        if($? == 0)
        {
            return 1;
        }
    }

    return 0;
}

sub killPid
{
    my $pid 	= shift;

    if($pid =~ /^\d+$/)
    {
        my $fnret =	`kill -9 $pid`;
        if($? != 0)
        {
            Logger::warn("Error when killing pid $pid : $fnret -- $!");	
            return 0;
        }
    }
    else
    {
        Logger::warn("PID $pid is invalid, cannot kill it !");
        return 0;
    }

    return 1;
}

sub isYubikeyOTPValid
{
    my $otp 	= shift;

    if($otp)
    {
        my $cmd		= 'wget -O- "https://api.yubico.com/wsapi/verify?id=13042&otp=' . $otp . '" 2> /dev/null';
        my $fnret 	= `$cmd`;

        if( $fnret =~ /status=OK/ )
        {
            return 1;
        }
    }

    return 0;
}

sub listScreens
{
    my $cmd   	= 'screen -ls';
    my $fnret 	= `$cmd`;
    my $screens = [];

    my @lines = split('\n',$fnret);

    foreach my $line ( @lines )
    {
        my ($pid,$name,$dateCreation,$status);
        if($line =~ /^\s(\d+)\.(\S+).*\((.*)\).*\((.*)\)$/)
        {
            ($pid,$name,$dateCreation,$status) = ($1,$2,$3,$4);
        }
        else
        {
            next;
        }	

        my $screen 	= {
            pid 		=> $pid,
            name		=> $name,
            creation	=> $dateCreation,
            status		=> $status,
        };

        push @{$screens}, $screen;
    }

    return $screens;
}


1;
