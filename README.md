##Pubkeytool

Pubkeytool (pkt) is a simple, lightweight commandline-tool for verification and encryption using asymmetric keys (public/private keypairs). 
It supports RSA, ECC and DSA. It also has some utility-commands for hashing and BASE64-(de)coding. 
Pubkeytool was written for use on minimalistic hardware, such as embedded systems, for which OpenSSL is too heavy. 
Currently, pkt uses [LibTomCrypt](https://github.com/libtom/libtomcrypt), as it has a sufficiently small footprint and an unrescrictive license.
However, it can easily be modified or extended to use another backend.

