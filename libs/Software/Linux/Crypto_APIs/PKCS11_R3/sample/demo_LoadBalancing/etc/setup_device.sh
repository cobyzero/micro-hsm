#This is a sample file for PKCS11_R3 for Linux



#!/bin/bash

#The script is used for preparing the device and setting the users and key pairs needed to execute the sample

#Note: The $1 parameter is used as a value to pass the device name.. For example: 3001@127.0.0.1





export AUTH=LOGONSIGN=ADMIN,$1/Administration/key/ADMIN.key

set -x

#delete user in case they already exist: (to avoid error when adding)

$1/Administration/csadm Dev=$2 $AUTH deleteuser=SO_0000 >/dev/null 2>&1

$1/Administration/csadm Dev=$2 $AUTH deleteuser=USR_0000 >/dev/null 2>&1


#add needed users

$1/Administration/csadm Dev=$2 $AUTH adduser=SO_0000,0200{CXI_GROUP=SLOT_0000},hmacpwd,12345678

$1/Administration/csadm Dev=$2 $AUTH adduser=USR_0000,0002{CXI_GROUP=SLOT_0000},hmacpwd,12345678

#Create key pair

$1/Administration/p11tool2 loginuser=12345678 slot=0 pubkeyattr=cka_label="test RSA key (pub)",cka_id="0" prvkeyattr=cka_label="test RSA key (prv)",cka_id=0x30 generatekeypair=RSA

set +x
