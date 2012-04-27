<?php
/**
 *
 * A PKCS12 container, storing a certificate and public and private keys.
 * @author Anders
 * @property PublicKey $publicKey
 * @property PrivateKey $privateKey
 * @property X509Certificate $certificate
 *
 */
class PKCS12 extends KeyStore {
	
	private $X509Certificate = null;
	private $privateKey = null;
	
	/**
	 * Represents a PKCS12 keystore.
	 * @param string $contents The contents of the PKCS12 keystore.
	 */
	public function __construct($contents, $passphrase) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		
		if(!openssl_pkcs12_read($contents, $keystore, $passphrase))
			throw new KeyStoreDecryptionFailedException(
				'Could not decrypt the certificate, the passphrase is incorrect, '.
				'its contents are mangled or it is not a valid PKCS #12 keystore.');
		$this->X509Certificate = new X509Certificate($keystore['cert']);
		$this->privateKey = new PrivateKey($keystore['pkey']);
	}
	
	/**
	 * Initialize the PKCS12 keystore from a file.
	 * @param string $keystoreLocation
	 * @throws FileNotFoundException
	 * @throws FileNotReadableException
	 */
	public static function initFromFile($keystoreLocation, $passphrase) {
		if(!file_exists($keystoreLocation))
			throw new FileNotFoundException("The keystore file '$keystoreLocation' does not exist.");
		if(!is_readable($keystoreLocation))
			throw new FileNotReadableException("The keystore file '$keystoreLocation' is not readable.");
		return new self(file_get_contents($keystoreLocation), $passphrase);
	}
	
	public function __get($name) {
		switch($name) {
			case 'publicKey':
				return $this->X509Certificate->publicKey;
			case 'privateKey':
				return $this->privateKey;
			case 'certificate':
				return $this->X509Certificate;
			default:
				return null;
		}
	}
}
