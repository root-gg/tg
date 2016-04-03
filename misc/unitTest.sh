#!/bin/bash

TG='/home/mbodjiki/git/tg/tg'

echo
echo "Creating host, alias, command alias..."
$TG -a 88.190.229.21
$TG -a 88.190.229.22
$TG -aa kikoo 88.190.229.21
$TG -aca mycmd kikoo -- uname -a
$TG -su root kikoo
$TG -sp 555 kikoo


echo 
echo "Verifiying that it is ok"
$TG -ls | grep "88.190.229.21"


echo 
echo "Setting email and phone..."
$TG -se mathieu@bodjikian.fr
$TG -sn 0674612987


echo
echo "Trying to delete things that does not exists"
$TG -rca kjifos
$TG -ra kjifos
$TG -r kjifos


echo 
echo "Trying to insert shit..."
$TG -se mathieu@@K..fr
$TG -sn 067461298fff

echo 
echo "Trying create doublons..."
$TG -aa kikoo 88.190.229.22 
$TG -aca mycmd kikoo -- uname -a


echo
echo "Deleting mess..."
$TG -rca mycmd
$TG -ra kikoo
$TG -r 88.190.229.21
$TG -r 88.190.229.22


