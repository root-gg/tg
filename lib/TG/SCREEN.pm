#!/usr/bin/perl

use strict;
use warnings;

package TG::SCREEN;

our $debug;
our $quiet;

sub new {
    my $class  = shift;
    my $params = shift;
    my $this   = {};

    $this->{'name'} 	= $params->{'name'};
    $this->{'user'}		= $params->{'user'} || $ENV{'USER'};
    $this->{'exec'} 	= $params->{'exec'};

    $this->{'options'} 	= $params->{'options'};
    $this->{'options'}  ||= {
        mode 			=> 'singleuser',
        detachOnCreate 	=> 0,
    }; 

    bless $this, $class;
    return $this;
}

sub name
{
    my $this = shift;

    my $name = "";
    $name .= $this->{'user'}."/" if $this->{'user'};
    $name .= $this->{'name'};

    return $name;
}

sub create
{
    my $this	= shift;

    my $cmd = "/usr/bin/screen -m";

    $cmd .= ' -d' ;#if $this->{'options'}->{'detachOnCreate'};
    $cmd .= ' -S ' . $this->{'name'}. " " .$this->{'exec'};

    Logger::info($cmd);

    `$cmd`;

    if ( $? == 0 )
    {
        Logger::info("Screen " . $this->{"name"} . " creation success");
    }
    else
    {
        Logger::warn("Screen " . $this->{"name"} . " creation fail");
        exit;
    }
}

sub isAlive
{
    my $this = shift;
    return 1;
}

sub send
{
    my $this 		= shift;
    my $command 	= shift;

    if ( $this->isAlive )
    {
        my $cmd 	= '/usr/bin/screen -S '. $this->name . " -X $command";
        my $fnret 	= `$cmd`;

        if ( $? == 0 )
        {
            Logger::info("Successfully sent $cmd to screen " . $this->{"name"}); 
        }
        else
        {
            Logger::warn("Failed to send $cmd to screen "  . $this->{"name"} . " : " . $fnret);
        }
    }
    else
    {
        Logger::warn("Screen ". $this->name." is not alive");
    }
}

sub join
{
    my $this = shift;

    exec "screen -x ".$this->name;
}

sub list
{
    my $this = shift;
    exec "screen -ls";
}

sub wipe
{
    my $this = shift;
    exec "screen -wipe";
}

sub kill
{
    my $this = shift;
    $this->send('quit');
}

sub allowUser
{
    my $this 		= shift;
    my $user 		= shift;
    my $password 	= shift || "";

    unless ( $user )
    {
        Logger::warn("No user found");
        return;
    }

    $this->send("multiuser on");
    $this->send("acladd $user $password");	
}

sub setPassword
{
    my $this        = shift;
    my $password    = shift || "";

    $this->send("password $password");
}

1;

