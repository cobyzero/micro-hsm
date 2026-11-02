=============================================
Learning PKCS#11 in Half a Day - Sample Files
=============================================


    Introduction
    Content of the folder PKCS11_HandsOn
    Prerequisites
        Windows
        Linux
    Running the example of section 3.3.5
        Windows
        Linux
    Compiling the sample files
        Windows
        Linux


Introduction
============

This folder contains the sample files explained in the guide "Learning PKCS#11 in Half a Day". 
Code details, which have been left out in the printout version for better readability, are available here. 
This includes, for examples, proper error catching and a command-line option, which communicates the path to the dynamic link library file. 

The printout pdf-version of the guide can be found on the CryptoServer product CD under ``Documentation\Crypto_APIs\PKCS11_R3``.
 

Content of the folder ``PKCS11_HandsOn``
========================================

The directories have the following content:

bin     
        Compiled executables will be placed here. Go here to run one of the sample programs.
etc
        The default administration key ``ADMIN.key`` for the HSM simulator is found here. The function ``EnsureUserExistence()`` needs it to create a Security Officer (SO) and a USER.
include
        The header file ``pkcs11_handson.h``, as explained in the learning guide, is located here.
mak
        If you are a Linux user, you'll find a Makefile here, which allows you to compile all samples. Adjust the ``Makefile`` to fit your system settings by editing the file ``config.inc``.
obj
        The Makefile in folder ``mak`` expects this folder. Object files are placed here when building under Linux.
prj_xx
        These folders contain Visual C++ project files for compilation under Windows. Executables will be placed in the folder ``bin``. It expects the PKCS#11-header files to be placed in ``%CS_PATH%\Software\PKCS11_R3\include``. ``%CS_PATH%`` is automatically set by the installer.
src
        All sample source files as explained in the learning guide can be found here.
 

Prerequisites
=============

We assume for all up-coming sections, that you've already done the following steps.

Windows
-------

You've already launched the Windows CryptoServerSetup installer on the CryptoServer product CD. 
The installer automatically sets several environment variables, like  ``%CS_PKCS11_R3_CFG%`` and ``%CS_PATH%``

Linux
-----

First copy from the CryptoServer product CD - depending on your system - either the folder ``Software/Linux/x86-32/Crypto_APIs/PKCS11_R3`` or the folder  ``Software/Linux/x86-64/Crypto_APIs/PKCS11_R3`` to a location, where you have write permissions. 
This location will be referred to as <your sample location>. 
You have as well already copied from the CD the folder ``Software/Linux/Simulator/sim5_linux`` to a location of your convenience. 
This new simulator location will be referred to as <your simulator location>. 
You've also payed attention, that you have write permissions on all files and folders in the new simulator location. 

 
Running the example of section 3.3.5
====================================

For your convenience, the last example in the guide is already available as exectuable in folder ``bin``. 
In order to run a PKCS#11 application you'll first have to adapt the PKCS#11 configuration file ``cs_pkcs11_R3.cfg``.

Windows
-------

We assume here, that you've already read the section Prerequisites.

Find first the location of your configuration file. Open a DOS command-line window and type

    echo %CS_PKCS11_R3_CFG%
    
The path to the configuration file ``cs_pkcs11_R3.cfg`` will show up. If you want to use for test purposes the HSM simulator (an icon should have been place on your Desktop after installation), then edit the line under ``[CryptoServer]`` in the configuration file to

    [CryptoServer]
    # Device specifier (here: CryptoServer is CSLAN with IP address 192.168.0.1) 
    Device = 3001@127.0.0.1
    
Save the configuration file. Then start the HSM simulator by clicking on the simulator icon.

Then go to folder ``bin``. Open a DOS command-line interface in folder ``bin`` and type:

    main_3.3.5_VerifySignedData.exe -LIB "%CS_PATH%\Lib\cs_pkcs11_R3.dll"

Linux
-----

We assume here, that you've already read the section Prerequisites.
 
Check whether the environment variable for the configuration file is set. In a terminal type

    echo $CS_PKCS11_R3_CFG
    
If it is empty, then set this variable to the location of the PKCS#11 configuration file, which is: ``<your sample location>/PKCS11_R3/sample/cs_pkcs11_R3.cfg``. 
Open the configuration file and edit the line under the section``[CryptoServer]``, such that ``Device=`` is set to the IP or PCI address of your Cryptoserver. Or, alternatively, use the HSM simulator. 
For the simulator edit the line as follows:

    [CryptoServer]
    # Device specifier (here: CryptoServer is CSLAN with IP address 192.168.0.1) 
    Device = 3001@127.0.0.1

Save the configuration file. Then go to ``<your simulator location>/sim5_linux/bin`` and start the HSM simulator by calling ``cs_sim.sh`` in a terminal.

Open another terminal and go to folder ``<your sample location>/PKCS11_R3/sample/PKCS11_HandsOn/bin``. The dynamic link library file should be located three folders below in ``lib`` (``../../../lib/libcs_pkcs11_R3.so``). In folder ``bin`` type:


    ./main_3.3.5_VerifySignedData -LIB ../../../lib/libcs_pkcs11_R3.so


Compiling the sample files
==========================

We assume here, that you've already read the section Prerequisites.

Windows
-------

Choose the Visual Studio Version of your choice. Go to the corresponding folder ``prj_xx`` and open the file ``PKCS11_HandsOn.sln`` with Visual C++.  
The paths to the header files should already properly be set. The following header files are needed: ``cryptoki.h``, ``pkcs11.h``, ``pkcs11f.h``, ``pkcs11t.h``, ``pkcs11t_cs.h``, ``pkcs-11v2-20a3.h``, ``pkcs11_handson.h`` 

You can either compile each section out of the "Learning PKCS#11 in Half a Day" guide by itself or all at once. 
In order to compile all at once, got to ``Build -> Build Solution``. In order to compile, for example, ``main_3.2.3``, select ``main_3.2.3`` and go to ``Build -> Project Only -> Build only main_3.2.3``. Pay attention under which platform (x64 or Win32) you are compiling. The dynamic library which you link at runtime has to match the platform you compiled for !

The executables are found in the ``bin`` folder.

Linux
-----

In order to compile the sample files under Linux, use the ``Makefile`` in the folder ``<your sample location>/sample/mak``. 
Adjust the ``Makefile`` to fit your needs by editing the following variables in the file ``<your sample location>/sample/PKCS11_HandsOn/mak/config.inc``.

CC
            Adjust the path to your C compiler executable.
INC_DIR_P11
            Adjust the path to the PKCS#11 header files (``cryptoki.h``, ``pkcs11.h``, ``pkcs11f.h``, ``pkcs11t.h``, ``pkcs11t_cs.h``, ``pkcs-11v2-20a3.h``). 

Enter the folder ``<your sample location>/sample/PKCS11_HandsOn/mak``. Type ``make`` to compile all sample files. Type ``make clean`` to remove all executables and object files. Type ``make 3.2.1`` if you only want to compile the main sample file in section 3.2.1 of the guide "Learning PKCS#11 in Half a Day".

The executables are found in the ``<your sample location>/sample/PKCS11_HandsOn/bin`` folder.