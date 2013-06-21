XenVbd - The XenServer Windows Virtual Block Device Driver
==========================================

XenVbd consists of two device drivers:

*    XenVbd.sys is a virtual block device driver.  XenVbd replaces the
     emulated disk device with a faster paravirtual block device allowing
     for faster reads and writes from and to the disk.

*    XenCrsh.sys is a library which provides the code to support XenVbd acting
     as a crashdump driver.  This is used to write crashdumps to the virtual 
     block device in the event of an error.

Quick Start
===========

Prerequisites to build
----------------------

*   Visual Studio 2012 or later 
*   Windows Driver Kit 8 or later
*   Python 3 or later 

Environment variables used in building driver
-----------------------------

MAJOR\_VERSION Major version number

MINOR\_VERSION Minor version number

MICRO\_VERSION Micro version number

BUILD\_NUMBER Build number

SYMBOL\_SERVER location of a writable symbol server directory

KIT location of the Windows driver kit

PROCESSOR\_ARCHITECTURE x86 or x64

VS location of visual studio

Commands to build
-----------------

    git clone http://github.com/xenserver/win-xenvbd
    cd win-xenvbd
    .\build.py [checked | free]

Device tree diagram
-------------------


    XenVbd--(XenCrsh)
       |
    XenBus
       |
    PCI Bus      
