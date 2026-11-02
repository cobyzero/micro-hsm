#This is a sample file for JCE Linux



#!/bin/bash

#The script is used for preparing the device and setting the users and key pairs needed to execute the sample

#Note: The $1 parameter is used as a value to pass the device name.. For example: 3001@127.0.0.1





export AUTH=LOGONSIGN=ADMIN,$1/Administration/key/ADMIN.key



#delete user in case they already exist: (to avoid error when adding)

$1/Administration/csadm Dev=$2 $AUTH deleteuser=JCE >/dev/null 2>&1


#add needed users

$1/Administration/csadm Dev=$2 $AUTH adduser=JCE,00000002{CXI_GROUP=*},hmacpwd,123456789


#the user needs to change the password first

$1/Administration/csadm Dev=$2 logonpass=JCE,123456789 changeuser=JCE,12345678



