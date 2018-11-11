# DigitalSigner
Digital Signer library it's a Java library which allows using apposite hardware for data signing.

### What Kind Of Operating Systems It Support?
On Windows it does only work under a 32bit JVM, because of the implementation of the Bit4Id library.
On Linux it works on both 32bit and 64bit machines as expected.
On MacOS, I tested only on 64Bit machines (running Sierra).

### What Types Of Card It Support?
Currently, it supports the Italian CNS (Carta Nazionale dei Servizi) and DS (Digital Signer) cards.
Other developers can request modifications to make this library work with their cards.

### Known Bugs
On Windows, if you disconnect, then reconnect the hardware, calling "signData" method will give you an exception. This does not happen on Linux, nor MacOS.

# How To Use
< to do>
