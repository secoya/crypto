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

### Signing with a private key from a keystore ###

Given a PKCS #12 keystore the library can extract the private key and sign any message with it, returning the signature:

```php
<?php
try {
	$passphrase = 'keystore passphrase';
	$keyStore = PKCS12::initFromFile('path/to/keystore.pkcs12', $passphrase);
	$signature = $keyStore->privateKey->sign($message);
} catch(KeyStoreDecryptionFailedException $e) {
	die('Wrong passphrase.');
}
return $signature;
```

### Verifying a signature ###

To verify a signature against a message you simply need the X509Certificate holding the public key that corresponds to the private key the message was signed with.

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



### Signing with an openssh private key ###

OpenSSH private keys are also handled by this library.
```php
<?php
try {
	$passphrase = 'private key passphrase';
	$privateKey = PrivateKey::initFromFile('~/.ssh/id_rsa', $passphrase);
	$signature = $privateKey->sign($message);
} catch(PrivateKeyDecryptionFailedException $e) {
	die('Wrong passphrase.');
}
return $signature;
```
