#!/bin/bash

#The script is used for preparing the device and setting the users and key pairs needed to execute the sample

#Note: The $1 parameter is used as a value to pass the device name.. For example: 3001@127.0.0.1

#export CRYPTOSERVER=3001@127.0.0.1

export SDK_PORT=3001

export ADM_PATH=$HOME'/samples/Linux/x86-64/Administration'

#$ADM_PATH/../sim5_linux/bin/bl_sim5



#export AUTH=LOGONSIGN=ADMIN,$ADM_PATH/key/ADMIN.key
export AUTH=LOGONSIGN=ADMIN,$1/Administration/key/ADMIN.key




#Delete user in case they already exist:(to avoid error when adding)

$1/Administration/csadm Dev=$2 $AUTH deleteuser=CXI_USER >/dev/null 2>&1 

$1/Administration/csadm Dev=$2 $AUTH adduser=CXI_USER,00000002{CXI_GROUP=test},hmacpwd,12345678

#java -jar $ADM_PATH/cat.jar



