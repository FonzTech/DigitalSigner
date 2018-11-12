# DigitalSigner
Digital Signer library it's a Java library which allows using smart cards for data signing in CAdES format.
You can also do Client Certificate Authentication with this library.

#### Small Note
When you look at source code, I use the term `hardware` instead of `smart card` because it's more generic.

***

### What Kind Of Operating Systems It Support?
On Windows it does only work under a 32bit JVM, because of the implementation of the Bit4Id library.
On Linux it works on both 32bit and 64bit machines as expected.
On MacOS, I tested only on 64Bit machines (running Sierra).

### What Types Of Card It Support?
Currently, it has been tested with the Italian CNS (Carta Nazionale dei Servizi) and DS (Digital Signer) cards, provided by Bit4Id®.
Other developers can request modifications to make this library work with their cards.

### Known Bugs
On Windows, if you disconnect, then reconnect the hardware, calling "signData" method will give you an exception. This does not happen on Linux, nor MacOS.

### Required Dependencies
This library depends on BouncyCastle. It requires both Provider and S/MIME API provided by the 1.6 version, specifically. Other versions will not work correctly, because some functions have been deprecated.

```xml
<dependencies>
  <dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcprov-jdk16</artifactId>
		<version>1.45</version>
	</dependency>
	<dependency>
		<groupId>org.bouncycastle</groupId>
		<artifactId>bcmail-jdk16</artifactId>
		<version>1.45</version>
  </dependency>
</dependencies>
```

***

# Part One: Setup

First of all, this library is designed with a singleton pattern. So, we get the singleton istance
```java
DigitalSigner digitalSigner = DigitalSigner.getSingleton();
```

If you want to see debugging informations by both library and PKCS#11 implementation, we can enable or disable debug logging:
```java
digitalSigner.setDebugEnabled(true);
```

Then we must set the library path, which contains the PKCS#11 implementation and the password to access the hardware:
```java
digitalSigner.setLibPath("C:/Some/Path/pkcs11.dll");
```

Finally, we have to set the password for the hardware:
```java
digitalSigner.setPassword("12345678");
```

Optionally, we can set the slot unit (in string format). By default, its value is 0:
```java
digitalSigner.setSlot("0");
```

***

# Part Two: Using The Library
The library is pretty straightforward.

You can extract the content from a CAdES signed content (in P7M format, presumably) via this function:
```java
byte[] originalContent = digitalSigner.extractSignedContent(myContentInByteFormat);
```

You can sign, or countersign, in CAdES format any data you want, via this function:
```java
byte[] signedContent = digitalSigner.sign(myContentInByteFormat);
```

You can verify CAdES signed data, via this function. The code is pretty self-explanatory:
```java
VerifySignature vs = digitalSigner.verify(signedContent);
boolean isSignatureValid = vs.isVerified();
ArrayList<ArrayList<String[]>> subjects = getSubjects();
ArrayList<ArrayList<String[]>> issuers = getIssuers();
```

Methods `getSubjects` and `getIssuers` will return an `ArrayList`, where each row contains another `ArrayList`, containing a list of `String` array, which has always two elements. They are like a key/value pair, where the key is a certificate field.
Here's an example:
- Array of subjects / issuers
    - First Row
        - { "DN", "James Brown" }
        - { "C", "USA" }
        - { "CN", "james@email.com" }
        - etc...
    - Second Row
        - { "DN", "John Connor" }
        - { "C", "United Kingdom" }
        - { "CN", "john@email.com" }
        - etc...
    - etc...
- etc...        
  
You can get the long field name by doing:
```java
String name = VerifySignature.getFieldName("DN");
// name is equal to "Distinguished Name".
```

You can get the KeyStore, respecting the PKCS#11 standard, via this function:
```java
KeyStore myKeyStore = digitalSigner.loadKeyStorePKCS11();
```

The method below is designed specifically for Italian cards, which can have multiple certificates, one for signing and another one for accessing public online services.
```java
String alias = digitalSigner.getAliasForCNS();
```

***

# Bonus Part: Client Certificate Authentication
You can use `SSLContext` to achieve Client Certificate Authentication, and `X509KeyManager` to choose the certificate to be used, by defining its alias. Take a look at the `ClientCertAuth.java` class for further information about the process.
