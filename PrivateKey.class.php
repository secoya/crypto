<?php
class PrivateKey {
	
	private $keyResource = null;
	
	/**
	 * Holds a private key so you can sign or decrypt stuff with it, must be cleartext,
	 * since we need the binary format as well.
	 * @param string $privateKey
	 */
	public function __construct($privateKey, $passphrase = '') {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		
		$this->keyResource = openssl_pkey_get_private($privateKey, $passphrase);
		if($this->keyResource === false)
			throw new PrivateKeyDecryptionFailedException(
				'Could not decrypt the private key, the passphrase is incorrect, '.
				'its contents are mangled or it is not a valid private key.');
	}
	
	/**
	 * Initialize the private key from a file.
	 * @param string $privatekeyLocation
	 * @throws FileNotFoundException
	 * @throws FileNotReadableException
	 */
	public static function initFromFile($privatekeyLocation, $passphrase) {
		if(!file_exists($privatekeyLocation))
			throw new FileNotFoundException("The private key file '$privatekeyLocation' does not exist.");
		if(!is_readable($privatekeyLocation))
			throw new FileNotReadableException("The private key file '$privatekeyLocation' is not readable.");
		return new self(file_get_contents($privatekeyLocation), $passphrase);
	}
	
	/**
	 * Signs the data passed in the argument, returns the signature in binary format.
	 * @param mixed $data The data to be signed
	 * @param string $algoritm Which algorithm to use for signing
	 * @return binary
	 * @throws InvalidMessageDigestAlgorithmException
	 */
	public function sign($data, $algorithm = 'RSA-SHA256') {
		if(!in_array($algorithm, openssl_get_md_methods(true)))
			throw new InvalidMessageDigestAlgorithmException(
			"The digest algorithm '$algorithm' is not supported by this openssl implementation.");
		openssl_sign($data, $signature, $this->keyResource, $algorithm);
		return $signature;
	}
	
	/**
	 * Decrypts $data using this private key.
	 * @param mixed $data
	 * @return string
	 * @throws DecryptionFailedException
	 */
	public function decrypt($data) {
		if(!openssl_private_decrypt($data, $decrypted, $this->keyResource))
			throw new DecryptionFailedException('Failed decrypting the data with this private key.');
		return $decrypted;
	}
	
	/**
	 * Frees the resource associated with this private key.
	 * This is automatically done on destruct.
	 */
	private function free() {
		if($this->keyResource)
			openssl_pkey_free($this->keyResource);
		$this->keyResource = null;
	}
	
	public function __destruct() {
		$this->free();
	}
}
