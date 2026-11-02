================
JCE example
================


    Introduction
    Content of the folder JCE sample
    Prerequisites
        Both
        Windows
        Linux
    Running the example
        Windows
        Linux
    Compiling the example 
        Windows
        Linux
   


Introduction
============
    
It is highly recommended to read the Manual for System Administrators  

Further informations are available in
[CSADM]         CryptoServer LAN / CryptoServer – Command-line Adminstration Tool - csadm, Utimaco GmbH
[CSP11CAT]      CryptoServer LAN / CryptoServer – PKCS#11 CryptoServer Administration Tool, Utimaco GmbH

This sample will allow you to see few example running on the JCE Java API sample. 
This document here describes only how to install, compile and run the example.
 

Content of the folder ``JCE sample``
===================================================

The directories have the following content:

bin                 Compiled JAR files will be placed here. Go here to run the example program.

etc                 Scripts to create the users and key pairs

src                 The sample source file is found here

CryptoServer.cfg    Configuration file

pom.xml             pom file to build the sample

readme.txt          This text file explains the steps to be followed during installation

rsa.key             RSA key

rsa_enc.key         Encrypted RSA key
 

Prerequisites
=============

Both
----
jdk version greater or equal to 1.8.0_211-x64 should be installed
Apache Maven should be installed and (Optional, only without Internet connection)the local maven repository should contain bcprov-jdk18on dependency version 1.72 or higher

Windows
-------

You've already launched the Windows SecurityServer installer and the Windows CryptoServerSDK 
installer on the product CD. The installer automatically sets several environment variables, like  
"%CS_PKCS11_R3_CFG%" and "%CS_PATH%"
Please pay attention to use installer defaults, if not you might need to change some commands accordingly

CryptoServer SDK and SecurityServer create and use the same environment variables,

Please verify the following env vars are set:
     CS_PATH=C:\Program Files\Utimaco\SecurityServer\  
     CS_PKCS11_R3_CFG=C:\ProgramData\Utimaco\PKCS11_R3\cs_pkcs11_R3.cfg 
     CS_CNG_CFG=C:\ProgramData\Utimaco\CNG\cs_cng.cfg


Linux
-----

Copy the whole ``<cd>/Software/Linux`` folder from product CD 64bit to depending on your system to ``/home/<User>/samples``
You can find the samples for JCE now here: ``/home/<User>/samples/Linux/x86-64/Crypto_APIs/JCE/sample``
Please make sure to have READ and WRITE permissions in the folder ``samples``. 



Running the example
===================

Sometimes you need to enter the <Device> as specified in the following line 
<Device> = IP address(CSLAN)or PCI(CryptoServer)or 3001@127.0.0.1(simulator)

Windows
-------

Start the simulator from the Desktop(an icon would have been visible post installation) 
To use the simulator please make sure the following line in the configuration file ``sample\CryptoServer.cfg`` is set
 
        Device = 3001@127.0.0.1 
     
Save the configuration file. Then start the HSM simulator by clicking on the simulator icon. 

Once the HSM is running, and the example has been configured in ``etc``, then  go to folder ``bin\<platform>``. 
To run the sample, open in folder "bin" a DOS command-line interface and type:

        ..\etc\setup_device.bat "%CS_PATH%\Administration\ADMIN.key" <Device1>

Instead of CS_PATH, user can decide where he/she needs to locate the sample, just like below instance:

        C:\Program Files\Utimaco\SecurityServer\Software\JCE\sample\etc>setup_device.bat "C:\Program Files\Utimaco\SecurityServer\Administration\ADMIN.key" <3001@127.0.0.1>

Open a DOS command-line interface in folder ``sample`` and type: 

   java -cp <path to samples.jar>;<path to bcprov-jdk18on-1.72.jar>;<path to securityserver-jce.jar> <sample> <path to CryptoServer.cfg>

e.g.
        cd <your sample location>\JCE\sample
        java -cp bin\samples.jar;"C:\my_path\bcprov-jdk18on-1.72.jar";..\lib\securityserver-jce.jar defaults.bench_RSA CryptoServer.cfg

The following examples are available for test:
    bench_RSA
    cert_Import
    crypt_AES
    crypt_DES
    crypt_RSA
    hash
    hmac_AES
    hmac_DES
    key_Delete
    key_Generate
    key_Import
    key_List
    key_Wrap_AES
    key_Wrap_Inter
    key_Wrap_RSA
    mac_AES
    mac_DES
    prov_Info
    prov_Login
    sign_DSA
    sign_DSA_P1363Format
    sign_EC
    sign_ECDSA_P1363Format
    sign_RSA
       
	
Linux
-----

To use the simulator please make sure the following line in the configuration file ``sample/CryptoServer.cfg`` is set 
 
        Device = 3001@127.0.0.1 
     
Save the configuration file. Then start the HSM simulator via the following commands 
If you want to use the simulator you need to start it in a new terminal session with the following command:

	/home/<User>/samples/Linux/Simulator/sim5_linux/bin/cs_sim.sh

To run the sample, open in folder "bin" in a new terminal and type:

        export CRYPTOSERVER=<Device>
	export CS_PATH=/home/<User>/samples/Linux/x86-64/
	cd $CS_PATH/Crypto_APIs/JCE/sample/bin
	../etc/setup_device.sh $CS_PATH <Device1>
 
Execute the following command from the sample directory: 
       java -cp <path to samples.jar>:<path to bcprov-jdk18on-1.72.jar>:<path to securityserver-jce.jar> defaults.<sample> <path to CryptoServer.cfg>

e.g.
       cd <your sample location>/JCE/sample
       java -cp bin/samples.jar:/mypath/bcprov-jdk18on-1.72.jar:../lib/securityserver-jce.jar defaults.bench_RSA CryptoServer.cfg
       

 The following examples are available:
    bench_RSA
    cert_Import
    crypt_AES
    crypt_DES
    crypt_RSA
    hash
    hmac_AES
    hmac_DES
    key_Delete
    key_Generate
    key_Import
    key_List
    key_Wrap_AES
    key_Wrap_Inter
    key_Wrap_RSA
    mac_AES
    mac_DES
    prov_Info
    prov_Login
    sign_DSA
    sign_DSA_P1363Format
    sign_EC
    sign_ECDSA_P1363Format
    sign_RSA



Compiling the example
=====================

We assume here, that you've already read the section Prerequisites.

Windows
-------


Go to folder <your sample location>\JCE\sample`. Open a DOS command-line interface in folder ``sample`` and type:

       cd <your sample location>\JCE\sample
       mvn install:install-file -Dfile="..\lib\securityserver-jce.jar" -DgroupId=de.utimaco -DartifactId=securityserver-jce -Dversion=6.0.0 -Dpackaging=jar
       mvn clean install

Linux
-----

Go to folder <your sample location>\JCE\sample`. Open a new terminal and type:

      cd <your sample location>/JCE/sample
      mvn install:install-file -Dfile=../lib/securityserver-jce.jar -DgroupId=de.utimaco -DartifactId=securityserver-jce -Dversion=6.0.0 -Dpackaging=jar
      mvn clean install


