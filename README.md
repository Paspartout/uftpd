uftpd - minimal ftp server
==========================

uftpd is my attempt at writing a minimal ftp server.
It aims to be as simple as possible to support the use case of
transfering and managing files between two hosts in a trusted local network.

I tested it on my linux machine and using filezilla as a client.

Building
--------

Simply type `make` to build the library and example server.

API
---

The server can be used as a library. 
Look at the uftpd.h file for the exposed functions and main.c for an example
on how to use them.

