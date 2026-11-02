===========
CXI Example
===========
    
    Introduction
    Content of the folder cxi_example
    Prerequisites
      Windows
      Linux
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

This sample will allow you to see an example running on the CXI-API.  


Content of the folder "cxi_example"
===================================

The directories have the following content:

bin        Compiled executables will be placed here. Go here to run the example.

etc        Scripts to create the users and key pairs

obj        The Makefile in folder "mak" expects this folder. Object files are placed here when building 
           under Linux.
prj_xx     These folders contain Visual C++ project files for compilation under Windows. Several Visual 
           Studio versions are supported. Executables will be placed in the folder "bin". It expects the 
           PKCS#11-header files to be placed in "%CS_PATH%\Software\PKCS11_R3\include". "%CS_PATH%" is 
           automatically set by the installer.
src        The demo's source files are found here.

readme.txt This text file explains the steps to be followed during installation


Prerequisites:
==============

Windows:
-------
You have already launched SecuritySErver installer when you execute the sec serv installer
You've already launched the Windows SecurityServer installer and the Windows CryptoServerSDK 
installer on the product CD. The installer automatically sets several environment variables, like  
"%CS_PKCS11_R3_CFG%" and "%CS_PATH%"
Please pay attention to use installer defaults, if not you might need to change some commands accordingly

CryptoServer SDK and SecurityServer create and use the same environment variables,

Please verify the following env vars are set:
     CS_PATH=C:\Program Files\Utimaco\SecurityServer\  
     CS_PKCS11_R3_CFG=C:\ProgramData\Utimaco\PKCS11_R3\cs_pkcs11_R3.cfg 
     CS_CNG_CFG=C:\ProgramData\Utimaco\CNG\cs_cng.cfg

Linux:
-------

Copy the whole ``<cd>/Software/Linux`` folder from product CD 64bit to depending on your system to ``/home/<User>/samples``
You can find the samples for CXI now here: ``/home/<User>/samples/Linux/x86-64/Crypto_APIs/CXI``
Please make sure to have READ and WRITE permissions in the folder ``samples``.


Running the example:
===================

Sometimes you need to enter the the <device> as specified in the following line 
<Device> = IP address(CSLAN)or PCI(CryptoServer)or 3001@127.0.0.1(simulator)

Windows:
-------

Start the simulator from the Desktop(an icon would have been visible post installation)
 
For your convenience, the example is already available as exectuable in folder: 

"C:\Program Files\Utimaco\SecurityServer\Software\CXI\sample\cxi_example\bin"

To run the sample, open in folder "bin" a DOS command-line interface and type:

	
	..\etc\setup_device.bat "%CS_PATH%\Administration\ADMIN.key" <Device>
	cxi_demo.exe cfg=..\etc\cxi.cfg

Instead of CS_PATH, user can decide where he/she needs to locate the sample, just like below instance:

        C:\Program Files\Utimaco\SecurityServer\Software\CXI\sample\cxi_example\bin\etc\setup_device.bat "C:\Program Files\Utimaco\SecurityServer\Administration\ADMIN.key" <Device>

Linux:
------

If you want to use the simulator you need to start it in a new terminal session with the following command 
	/home/<User>/samples/Linux/Simulator/sim5_linux/bin/cs_sim.sh

To run the sample, open in folder "bin" a terminal and type:
	export CRYPTOSERVER=<Device>
	export CS_PATH=home/<User>/samples/Linux/x86-64  #Possible ~will not work in all cases and needs to be changed to the absolute path)
	cd /home/<User>/samples/Linux/x86-64/Crypto_APIs/CXI/sample/cxi_example/bin
	../etc/setup_device.sh $CS_PATH <Device>
	./cxi_demo cfg=../etc/cxi.cfg

 
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

In order to compile the sample files under Linux, use the ``Makefile`` in the folder ``<your sample location>/sample/cxi_example/mak``. Adjust the ``Makefile`` to fit your needs by editing the following variables in the file ``<your sample location>/sample/cxi_example/mak/config.inc``.

CC
            Adjust the path to your C++ compiler executable.
INC_DIR
            Adjust the path to the CXI header files (<your sample location>/include). 
LIB_PATH    
            Adjust the path to the CXI library (<your sample location>/lib).

Enter the folder ``<your sample location>/sample/cxi_example/mak``. Type ``make`` to compile all sample files. Type ``make clean`` to remove all executables and object files. 

You'll find the executable in folder ``<your sample location>/sample/cxi_example/bin/<platform>``.