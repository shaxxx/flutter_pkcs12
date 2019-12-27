# flutter_pkcs12

Flutter plugin that allows you to use PKCS12 (p12) keystore for digital signing.
Result of signing is RSA signature with PKCS1 padding.

## Source code

This project is heavily based on 
[flutter_p12 plugin](https://github.com/Dviejopomata/flutter-p12).
I decided to move it to new plugin because
- i expect same signature result on Android & iOS using same input parameters which is not the case in the original plugin
- i need a way to specify hash algorithm to be used during signing
- i don't want to polute plugin with unsupported APIs or only partially supported (Android only)

## Features

All features are implemented on Android & iOS.

Only 2 methods are provided `signDataWithP12` and `readPublicKey`

`signDataWithP12` expects p12 keystore file as bytes (ie. from filesystem or from assets), password used to decrypt the key, data bytes to be signed and hash method to be used.

Data bytes are usually encoded string (ie. `utf8.encode("Some data");` if you're using utf8 encoding) **BEFORE** hashing. Do not hash your data before using it as signing parameter. Native plugin will take care of that. You'll have to choose what hash algorithm to use. Curently supported are

- SHA1
- SHA256
- SHA512

While there are other possible hash algorithms I decided to use only these since they are most used and implemented on both platforms.
MD5 is considered insecure and unsupported as of iOS 5.0.

For more details check [Android](https://developer.android.com/reference/java/security/Signature) & [iOS](https://developer.apple.com/documentation/security/secpadding) documentation.

`readPublicKey` reads public key from p12 file and returns it as Base64 string.

For more details check out [example](https://github.com/shaxxx/flutter_pkcs12/tree/master/example)
