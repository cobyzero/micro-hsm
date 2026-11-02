===========================
PKCS#11 Load Balancing Demo
===========================


    Content of the folder demo_LoadBalancing
    Introduction
    Install the  SDK samples
        Windows
        Linux
    Running the load balancing demo
        Windows
        Linux
    Compiling the load balancing demo
        Windows
        Linux
    Configure hardware HSM devices


Content of the folder "demo_LoadBalancing"
============================================

The directories have the following content:

bin .................. Compiled executables will be placed here. Go here to run the example.

etc .................. Scripts to create the users and key pairs

include .............. The header file "demo_LoadBalancing.h" is located here.

mak .................. If you are a Linux user, you'll find a Makefile here, which allows you to compile the example.
                       Adjust the "Makefile" to fit your system settings by editing the file "config.inc".

obj .................. The Makefile in folder "mak" expects this folder. Object files are placed here when building
                       under Linux.

prj_xx ............... These folders contain Visual C++ project files for compilation under Windows.
                       Executables will be placed in the folder "bin". It expects the
                       PKCS#11-header files to be placed in "%CS_PATH%\Software\PKCS11_R3\include". "%CS_PATH%" is
                       automatically set by the installer.

src .................. The demo's source files are found here.

../cs_pkcs11_R3.cfg .. The default config file.

Introduction
============

It is highly recommended to read the load balancing sections in the Manual for System Administrators
[CSADMIN-LB] and the PKCS#11 developer guide [CSPKCS11].

[CSADMIN-LB]    CryptoServer LAN / CryptoServer – Manual for System Administrators,
                Utimaco GmbH - Section "Clustering for Load Balancing and Failover"
                Utimaco GmbH - Section "User Management"
[CSPKCS11]      CryptoServer PKCS#11 R3 Developer Guide,
                Utimaco GmbH - Section "Load Balancing Mode"

Further informations are available in
[CSADM]         CryptoServer LAN / CryptoServer – Command-line Adminstration Tool - csadm, Utimaco GmbH
[CSP11CAT]      CryptoServer LAN / CryptoServer – PKCS#11 CryptoServer Administration Tool, Utimaco GmbH

The demo allows you to compare the time needed for a certain set of 2048 bit RSA key pair generation,
sign or verify transactions between different cluster sizes. You can see how the computation time for
the same set of transactions scales with cluster size.

The sample configuration uses per default two HSM simulators. If you are not interested in performance,
but only in "how-it-works", then you can use the configured HSM simulator instances.  Performance with
HSM simulators is not at all comparable to that of real HSMs and depends on how busy your computer is
with other applications at the moment of running the demo. For hardware HSMs you reach the best
balancing result if you use HSMs of same model type. (Look to "Configure hardware HSM devices" if you
want to use hardware HSMs

The following settings in the configuration file "cs_pkcs11_R3.cfg" are mandatory:

    # Configures load balancing mode ( == 0 ) or failover mode ( > 0 )
    FallbackInterval = 0

    # Created/Generated keys are stored in an external or internal database
    KeysExternal = true
    KeyStore = C:/ProgramData/Utimaco/PKCS11_R3/P11.pks

    # Path to the external keystore
    # If KeyStore is defined the external keystore will be created and used at the defined location
    # Use the actual workdir, maybe changed to a more static location
    KeyStore = ../bin/P11.pks


Install the SDK samples
=======================

Windows
-------

You've already launched the Windows SecurityServer installer and the Windows CryptoServerSDK
installer on the product CD. The installer automatically sets several environment variables, like
"%CS_PKCS11_R3_CFG%" and "%CS_PATH%"

Linux
-----

Copy the whole ``<cd>/Software/Linux`` folder from product CD 64bit to depending on your system to ``/home/<User>/samples``
You can find the samples for PKCS11_R3 now here: ``/home/<User>/samples/Linux/x86-64/Crypto_APIs/PKCS11_R3/sample``
Please make sure to have READ and WRITE permissions in the folder ``samples``.




Running the load balancing demo
===============================

For your convenience the executable is already available in folder "bin".


Windows
-------

To start the HSM simulators, open in folder "bin" a DOS command-line interface and type:

             %CS_PATH%\Simulator\bin\cs_multi.bat 2

To run the sample, open in folder "bin" another DOS command-line interface and type:

             set CS_PKCS11_R3_CFG=%CS_PATH%\Software\PKCS11_R3\sample\cs_pkcs11_R3.cfg

             ..\etc\setup_device.bat "%CS_PATH%\Administration\ADMIN.Key" 3001@127.0.0.1
             or
             setup_device.bat "C:\Program Files\Utimaco\SecurityServer\Administration\ADMIN.key" 3001@127.0.0.1

             ..\etc\setup_device.bat "%CS_PATH%\Administration\ADMIN.Key" 3003@127.0.0.1
             or
             setup_device.bat "C:\Program Files\Utimaco\SecurityServer\Administration\ADMIN.key" 3003@127.0.0.1

             demo_LoadBalancing.exe -LIB "%CS_PATH%\Lib\cs_pkcs11_R3.dll"  -keyGen 2 -sign 10 -verify 20


Linux
-------

To start the HSM simulators, open in folder "bin" a terminal and type:

             export CS_PATH=~/samples
             $CS_PATH/Simulator/sim5_linux/bin/cs_multi.sh 2

To run the sample, open in folder "bin" a DOS command-line interface and type:
             export CS_PATH=~/samples
             export CS_PKCS11_R3_CFG=$CS_PATH/Software/PKCS11_R3/sample/cs_pkcs11_R3.cfg

             or

             export CS_PKCS11_R3_CFG=~/samples/Linux/x86-64/Crypto_APIs/PKCS11_R3/sample/cs_pkcs11_R3.cfg

             ../etc/setup_device.sh <your sample location>/Linux/x86-64/ 3001@127.0.0.1
             ../etc/setup_device.sh <your sample location>/Linux/x86-64/ 3003@127.0.0.1
             demo_LoadBalancing -LIB <your sample location>/lib/libcs_pkcs11_R3.so  -keyGen 2 -sign 10 -verify 20
             or
             ./demo_LoadBalancing -LIB ~/samples/Linux/x86-64/Crypto_APIs/PKCS11_R3/lib/libcs_pkcs11_R3.so  -keyGen 2 -sign 10 -verify 20



Compiling the load balancing demo
=================================

Windows
-------

Choose the Visual Studio Version of your choice. Go to the Visual Studio project folder "prj_xx" and
open the file "PKCS11_HandsOn.sln" with Visual C++.
Pay attention under which platform (x64 or Win32) you are compiling. The dynamic library which you link
at runtime has to match the platform you compiled for:

The executables will show up in the "bin" folder.


Linux
-----

Enter the folder "<your sample location>/sample/demo_LoadBalancing/mak". Type "make" to compile all
sample files. Type "make clean" to remove all executables and object files.

The executables are found in the "<your sample location>/sample/demo_LoadBalancing/bin" folder.



Configure hardware HSM devices
==============================

To configure hardware devices simply change the "Device" setting in "cs_pkcs11_R3.cfg" and use the
device name instead of "300x@127.0.0.1" for the setup_device calls (see above)

