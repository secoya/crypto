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
	
	private $contents = null;
	
	private $X509Certificate = null;
	private $privateKey = null;
	
	private $locked = true;
	
	/**
	 * Represents a PKCS12 keystore.
	 * @param string $contents The contents of the PKCS12 keystore.
	 */
	public function __construct($contents) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		$this->contents = $contents;
	}
	
	/**
	 * Initialize the PKCS12 keystore from a file.
	 * @param string $certificateLocation
	 * @throws FileNotFoundException
	 * @throws FileNotReadableException
	 */
	public static function initFromFile($certificateLocation) {
		if(!file_exists($certificateLocation))
			throw new FileNotFoundException("The certificate file '$certificateLocation' does not exist.");
		if(!is_readable($certificateLocation))
			throw new FileNotReadableException("The certificate file '$certificateLocation' is not readable.");
		return new self(file_get_contents($certificateLocation));
	}
	
	/**
	 * Unlocks the certificate with a passphrase.
	 * @param string $passphrase
	 */
	public function unlock($passphrase = null) {
		if(!openssl_pkcs12_read($this->contents, $content, $passphrase))
			throw new KeyStoreDecryptionFailedException(
				'Could not decrypt the certificate, the passphrase is incorrect, '.
				'its contents are mangled or it is not a valid PKCS #12 keystore.');
		$this->X509Certificate = new X509Certificate($content['cert']);
		$this->privateKey = new PrivateKey($content['pkey']);
		$this->locked = false;
	}

	/**
	 * Removes the parsed/unencrypted contents.
	 * This frees all resources associated with this keystore.
	 * So if the public/private key is referenced from somewhere else,
	 * it will not be accessible any longer.
	 */
	public function lock() {
		$this->X509Certificate = null;
		$this->privateKey->free();
		$this->privateKey = null;
		$this->locked = true;
	}
	
	public function __get($name) {
		if($this->locked)
			throw new KeyStoreLockedException('The certificate you are trying to access is locked.');
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
