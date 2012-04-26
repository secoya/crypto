<?php
class PublicKey {
	
	public $keyResource = null;
	
	public function __construct($certificate) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		$this->keyResource = openssl_pkey_get_public($certificate);
	}
	
	/**
	 * Verifies that the data and the signature belong to this public key.
	 * Returns true on success, false on failure.
	 * @param mixed $data The data to be verified
	 * @param mixed $signature The signature of the data
	 * @param string $algoritm Which algorithm to use for signing
	 * @return boolean
	 * @throws InvalidMessageDigestAlgorithmException
	 */
	public function verify($data, $signature, $algorithm = 'RSA-SHA256') {
		if(!in_array($algorithm, openssl_get_md_methods(true)))
			throw new InvalidMessageDigestAlgorithmException(
			"The digest algorithm '$algorithm' is not supported by this openssl implementation.");
		return openssl_verify($data, $signature, $this->keyResource, $algorithm) == 1;
	}
	
	/**
	 * Decrypts $data using this public key.
	 * @param mixed $data
	 * @return string
	 * @throws DecryptionFailedException
	 */
	public function decrypt($data) {
		if(!openssl_public_decrypt($data, $decrypted, $this->keyResource))
			throw new DecryptionFailedException('Failed decrypting the data with this public key.');
		return $decrypted;
	}
	
	public function __destruct() {
		if($this->keyResource)
			openssl_free_key($this->keyResource);
		$this->keyResource = null;
	}
}
