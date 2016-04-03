#!/usr/bin/perl

package Logger;

use strict;
use warnings;
use Exporter;
use DateTime;
use FileHandle;
use Term::ANSIColor qw(:constants colored);
use vars qw($VERSION @ISA @EXPORT);

our $debug;

@ISA	= qw(Exporter);
@EXPORT = (
    'Logger::debug',
    'Logger::debug1',
    'Logger::debug2',
    'Logger::debug3',
    'Logger::notice',
    'Logger::info', 
    'Logger::warn',
    'Logger::crit',
    'Logger::expect',
);


my $LogPath = $ENV{'HOME'};
my $LogFile = $LogPath . '/TG.log';


# Create file if not exist 
if( ! -e $LogFile)
{
    my $fnret = `touch $LogFile`;

    if($? != 0)
    {
        print "Failed to create logfile $LogFile : $fnret \n";
    }
}


# Open filehandle
my $LogFilehandle   = FileHandle->new;
my $fnret           = $LogFilehandle->open(">> $LogFile"); 

if(!$fnret)
{
    print "Can't init Logger !!!! \n";
}


sub Logger::info
{
    Logger(shift, 'INFO',    shift);
}

sub Logger::warn
{
    Logger(shift, 'WARNING', shift);
}

sub Logger::crit
{
    Logger(shift, 'CRITICAL', shift);
}

sub Logger::expect
{
    Logger(shift, 'EXPECT',  shift);
}

sub Logger::notice
{
    Logger(shift, 'NOTICE',  shift);
}

sub Logger::debug
{
    if($debug and $debug >= 1)
    {
        Logger(shift, 'DEBUG1', shift);
    }
}

sub Logger::debug2
{
    if($debug and $debug >= 2)
    {
        Logger(shift, 'DEBUG2', shift);
    }
}


sub Logger::debug3
{
    if($debug and $debug >= 3)
    {
        Logger(shift, 'DEBUG3', shift);
    }
}

sub Logger
{
    my $message = shift 		|| return; 
    my $level   = shift 		|| 'INFO';
    my $params  = shift;
    my $save	= 1 			if !$params->{'save'};

    # Splitting 
    my @Messages            = split("\n", $message);

    foreach(@Messages)
    {
        # Building message
        my $finalMessage 	= sprintf "[%-9s] %s" 	,$level,$_;

        # We print
        print YELLOW 		if $level eq 'WARNING';
        print RED 			if $level eq 'CRITICAL';
        print CYAN  		if $level eq 'INFO';
        print GREEN         if $level =~ /(EXPECT|NOTICE)/;
        print BRIGHT_BLACK  if $level =~ /^DEBUG/;

        print $finalMessage;

        print "\n"		if $level ne 'EXPECT';
        print RESET;  	

        # We save by default
        saveMessage($finalMessage) if $save;

        # Send to node
        require LWP::UserAgent;
        my $url 		= 'http://localhost:9999';
        my $ua       	= LWP::UserAgent->new();
        my $response 	= $ua->post( $url, { 'level' => $level , 'message' => $finalMessage });	
    }

    return 1;
}

sub saveMessage
{
    my $message = shift || 'Logger called with no message...';
    my $date	= DateTime->from_epoch( 
        epoch 		=> time(),
        time_zone	=> 'Europe/Paris', 
    );
    my $script  = sprintf "[%-15s]" ,$0;

    if($LogFilehandle)
    {
        print $LogFilehandle '['.$date->datetime.']' . $script .  $message . "\n"; 
    }
    else
    {
        print "Impossible to save Logger to file ! \n";
    }
}


1;
