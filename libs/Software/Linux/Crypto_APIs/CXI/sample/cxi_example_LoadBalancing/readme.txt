==========================
CXI Load Balancing Example
==========================


    Introduction
    Content of the folder cxi_example_LoadBalancing
    Prerequisites
        Windows
        Linux
        Both
    Setup
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

This sample will allow you to see an example running on the cxi_example_LoadBalancing. 
This document here describes only how to install, compile and run the example.
 

Content of the folder ``cxi_example_LoadBalancing``
===================================================

The directories have the following content:

bin         Compiled executables will be placed here. Go here to run one of the example program.

doc         This folder contains a pdf-document describing Utimaco's cluster feature and the example's use case in more detail.

etc         The cxi-API's (``cxi.cfg``) and the example's (``lb.cfg``) configuration files are located here. 

include     The content of the folder are the header files

prj_xx      These folders contain Visual C++ project files for compilation under Windows. Several Visual 
            Studio versions are supported. Executables will be placed in the folder "bin". It expects the 
            PKCS#11-header files to be placed in "%CS_PATH%\Software\PKCS11_R3\include". "%CS_PATH%" is 
            automatically set by the installer.

src         The sample source file is found here

mak         Make files for UNIX

readme.txt  This text file explains the steps to be followed during installation
 

Prerequisites
=============

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
You can find the samples for CXI now here: ``/home/<User>/samples/Linux/x86-64/Crypto_APIs/CXI/sample/cxi_example_LoadBalancing``
Please make sure to have READ and WRITE permissions in the folder ``samples``. 

Both
----

Configure the example. First set the devices you want to use. Specify their IP addresses or ports in ``etc/cxi.cfg``. 
Continue configuring the example by opening ``etc/lb.cfg``. It contains a lot of extensive comments. Good to read them. 


Running the example
===================

Sometimes you need to enter the <Device> as specified in the following line 
<Device> = IP address(CSLAN)or PCI(CryptoServer)or 3001@127.0.0.1(simulator)

Windows
-------

Start the simulator from the Desktop(an icon would have been visible post installation) 
To use the simulator please make sure the following line in the configuration file ``etc\cxi.cfg`` is set
 
        Device = 3001@127.0.0.1 3003@127.0.0.1
     
Save the configuration file. Then start the HSM simulator by clicking on the simulator icon. 
If you want to start two identical simulator instances,close the currently running simulator,open a DOS command-line interface and type:
        
        cd %CS_PATH%\Simulator\bin
        cs_multi.bat 2
 
Once the HSM is running, and the example has been configured in ``etc\lb.cfg``, then  go to folder ``bin\<platform>``. 
To run the sample, open in folder "bin" a DOS command-line interface and type:

        ..\etc\setup_device.bat "%CS_PATH%\Administration\ADMIN.key" <Device1>
        ..\etc\setup_device.bat "%CS_PATH%\Administration\ADMIN.key" <Device2>
	cxi_example_LoadBalancing.exe cfg=..\etc\lb.cfg

Instead of CS_PATH, user can decide where he/she needs to locate the sample, just like below instance:

      "C:\Program Files\Utimaco\SecurityServer\Software\CXI\sample\cxi_example_LoadBalancing\etc\setup_device.bat" "C:\Program Files\Utimaco\SecurityServer\Administration\ADMIN.key" <Device>
    

Linux
-----

To use the simulator please make sure the following line in the configuration file ``etc/cxi.cfg`` is set
 
        Device = 3001@127.0.0.1 3003@127.0.0.1
     
Save the configuration file. Then start the HSM simulator via the following commands 
If you want to start two identical simulator instances,close the currently running simulator,open a terminal and type:
        
        export CRYPTOSERVER=<Device>
	export CS_PATH=/home/<User>/samples/Linux
        cd $CS_PATH/Simulator/sim5_linux/bin 
        ./cs_multi.sh 2

Once the HSM or the simulator is running and the example has been configured in ``etc/lb.cfg``, then  go to folder ``bin/<platform>``.
To run the sample, open in folder "bin" a new terminal and type:

        export CRYPTOSERVER=<Device>
	export CS_PATH=/home/<User>/samples/Linux/x86-64/
	cd $CS_PATH/Crypto_APIs/CXI/sample/cxi_example_LoadBalancing/bin
	../etc/setup_device.sh $CS_PATH <Device1>
        ../etc/setup_device.sh $CS_PATH <Device2>
        ./cxi_example_LoadBalancing cfg=../etc/lb.cfg



Compiling the example
=====================

We assume here, that you've already read the section Prerequisites.

Windows
-------

Go to folder ``prj_14`` and open the file ``cxi_demo.sln`` with Visual Studio 2015.  
Pay attention under which platform (x64 or Win32) you are compiling. It has to fit your system architecture. 
You'll find your compiled executable in folder ``bin\<platform>``.

Linux
-----

In order to compile the sample files under Linux, use the ``Makefile`` in the folder ``<your sample location>/sample/cxi_example/mak``. 
Adjust the ``Makefile`` to fit your needs by editing the following variables in the file ``<your sample location>/sample/cxi_example/mak/config.inc``.

CC                Adjust the path to your C++ compiler executable.

INC_DIR           Adjust the path to the CXI header files (<your sample location>/include). 

LIB_PATH          Adjust the path to the CXI library (<your sample location>/lib).

Enter the folder ``<your sample location>/sample/cxi_example_LoadBalancing/mak`` and execute the make from command line 
       
       make clean
       make

You'll find the executable in folder

     ``<your sample location>/sample/cxi_example_LoadBalancing/bin/<platform>``.


