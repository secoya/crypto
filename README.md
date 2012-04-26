Certificate library
=====================

This library wraps the php openssl extension, allowing you to handle PKCS #12 keystores
in an object oriented way.

Functionality
-------------

Handling PKCS #12 keystores requires other features as well.
You can initialize X509 certificates using a base64 encoded string:
```php
<?php
$pemCert = 'base64 encoded string';
$certificate =  new X509Certificate($pemCert);
```
The certificate revocation list can be checked quite easily:
```php
<?php
$certificate->checkCRL(array('path/to/intermediate_certificates'));
```

### Exceptions ###
----------

All error reporting is based on exceptions. php_openssl usually requires you to check last_error
after an operation, the library does this for you and throws an exception if something failed.

Simple example
--------------

### Signing with a private key ###

Given a PKCS #12 keystore the library can extract the private key and sign any message with it, returning the signature:

```php
<?php
try {
	$keyStore = PKCS12::initFromFile('path/to/keystore.pkcs12');
	$keyStore->unlock('keystore passphrase');
	$signature = $keyStore->privateKey->sign($normalizedParameters);
} catch(KeyStoreDecryptionFailedException $e) {
	die('Wrong passphrase.');
}
return $signature;
```

### Verifying a signature ###

To verify a signature against a string you simply need the X509Certificate holding the public key that corresponds to the private key the string was signed with.

```php
<?php
$pemCert = 'base64 encoded string';
$certificate =  new X509Certificate($pemCert);
$valid = $certificate->publicKey->verify($message, $signature);
if($valid) {
	echo 'Signature is valid';
} else {
	echo 'Signature is invalid';
}
```
