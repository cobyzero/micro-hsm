echo This is a dummy file for PKCS11_HandsOn

echo .

echo Warning: This script will overwrite the token label, and also

echo overwrite SO_0000 and USR_0000, and reset their PINs to 12345678.

echo If you do not need this behavior, please do not run this script.

echo .

echo The script is used for preparing the device and setting the users

echo and any keys/key pairs needed to execute the sample

echo .

echo There are three parameters. For parameters that include paths,

echo use single forward:

echo ~/ADMIN.key

echo .

echo \$1 should supply the path to the login credentials of a user admin. 

echo If the factory default user ADMIN is used, this would be a path to the ADMIN.key

echo .

echo \$2 should be the locator string, like 3001@127.0.0.1 \(Simulator\)

echo or 288@<ip-address>, or PCI:0 for a PCIe HSM.

echo .

echo \$3 should be the config file \(cs_pkcs11_R3.cfg\) to use

echo The config file should point to the same device as in the second

echo parameter

echo .

echo Example:

echo setup_device.sh ~/ADMIN.key 3001@127.0.0.1 ./cs_pkcs11_r3.cfg

echo



export auth=ADMIN,$1

export CRYPTOSERVER=$2

export CS_PKCS11_R3_CFG=$3



echo --CREATE USERS

echo Try to delete user, should they already exist:

echo \(to avoid error when adding the user\)

csadm LogonSign=$auth DeleteUser=USR_0000 DeleteUser=SO_0000 >NUL 2>&1

echo Done 

echo .

echo --INITIALIZING SLOT 0

echo Create P11 SO with Pin 12345678
p11tool2 Login=$auth Force=1 Label=p11HandsOn InitToken=12345678

echo Create P11 USR with Pin 12345678

p11tool2 LoginSO=12345678 InitPin=12345678

echo Done

echo .

echo --Any keys?

echo None needed for HandsOn sample
