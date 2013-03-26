## csniffer

This project is a simple sniffer kernel module developed
as a faculty project for the Networking course. 

Requirements
------------

In order to compile this project you need to install: 
* linux-headers: Header files and scripts for building modules for linux kernel
* linux-api-headers: Kernel headers sanitized for use in userspace
* libnl: Library for applications dealing with netlink sockets
* libnl1: Library for applications dealing with netlink sockets (Legacy version)
* gtk

Install
-------

In order to install and run csniffer just issue the following

    $ make
    $ bash run.sh

Which will firts build the project, then run the `run.sh` script
that inserts the sniffer kernel module and display the front
end application (CLI or GTK based).

Kernel Version
--------------

This program was tested against linux kernel versions: 
* 3.3.x
* 3.4.x
* 3.7.x
