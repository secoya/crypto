<?php
class PrivateKey {
	
	private $keyResource = null;
	
	/**
	 * Holds a private key so you can sign or decrypt stuff with it, must be cleartext,
	 * since we need the binary format as well.
	 * @param string $privateKey
	 */
	public function __construct($privateKey) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		$this->keyResource = openssl_pkey_get_private($privateKey);
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
	 * This is automatically done on destruct. It can be invoked manually,
	 * if you want to make sure it can't be accessed from anywhere else,
	 * even though there is still a reference to it.
	 */
	public function free() {
		if($this->keyResource)
			openssl_pkey_free($this->keyResource);
		$this->keyResource = null;
	}
	
	public function __destruct() {
		$this->free();
	}
}
