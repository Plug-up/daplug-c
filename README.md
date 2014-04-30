The Daplug API source files are in the "src" directory.

The "test" directory contain a "main.c" file. So you can use it to understand how the C Daplug API works and what we can do with it. 

Last update 18 04 2014 10:57

## How to compile ##

### Windows 7/32 ###

- Install openssl for windows <Win32 OpenSSL v1.0.1f> or greater (http://slproweb.com/products/Win32OpenSSL.html)

- Install libusbx-1.0

- Linked libraries : libusb-1.0 (libusbx) + libeay32 (openssl) + setupapi

- When compiling, sets openssl and libusbx search directories (include & dll) : here we use dynamic linking ;
   so not forget to put dll files in the runtime directory when deploying.

- If driver problem, install it using zadig (http://zadig.akeo.ie/).

### Linux 64 (Tested on Ubuntu 13.10, should work on other releases) ###

- Linked libraries : libusb-1.0 + libcrypto (openssl) + libpthread (on 64 OS)

- Add proper udev rule.

- Add -fPIC to compiler options. (when creating a lib on 64)

## Notes ##

- Be careful ! Use the right hidapi (hidpai.c & hidapi.h) according to your OS !!!

- For debug use debug compilation ; for deploying use release compilation.

