# Digital Signing / Firma Digital

This is a pretty small Java8 project to help demonstrate how to sign text or a pdf using a Token USB.

Pequeño proyecto en Java8 para demostrar como firmar digitalmente texto o archivos pdf utilizando un Token USB.

## Set up

1. Clone the repository
2. It is a Maven project, install the dependencies as usual
3. Add as a referenced library to the project the jar file `sunpkcs11.jar` (found under java8-installation-path/`lib/ext/`).

## Example Usage
```java
// Create the instance which require the path of the library file, provided by the vendor.
UsbToken tokenUnix = new UsbToken("/my/path/library.so");
// windows library
// UsbToken tokenWin = new UsbToken("c:\\my\\path\\library.dll");

//Sign text
byte[] signValue = tokenUnix.signText("text to sign...", "passwordOfMyUsbToken");

//Validate the signature
boolean valid = new Notary().verifySignature("signed text...".getBytes(), signValue, 
                                                               tokenUnix.publicKey("passwordOfMyUsbToken"));

System.out.println("is valid?: " + valid);
		
//Signing a PDF File
tokenUnix.signPdf("/tmp/pdftoSign.pdf", "/tmp/signedPdf.pdf", "passwordOfMyUsbToken", "reason", "location");
```
