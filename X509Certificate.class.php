<?php
/**
 * Represents an X509 certificate
 * @author Anders
 * @property PublicKey $publicKey The public key of the certificate.
 * @property String $clearText Clear text base64 representation of the certificate.
 * @property string $compactBase64 Base64 encoded version of the certificate without linebreaks and delimiters.
 * @property array $info Information about the certificate. Contains things like the name and the fingerprint of the certificate.
 * @property string $commonName The CN of the certificate.
 * @property string $fingerprint The fingerprint of the certificate.
 * @property string $fingerprintCA The fingerprint of the certificate with which this certificate was signed.
 * @property boolean $isSelfSigned Whether the certificate is self signed.
 * @property boolean $isCA Whether the certificate is a certificate authority.
 * @property X509Certificate $issuer The issuer of this certificate. Is null if not set explicitely.
 * @property DateTime $validFrom From when the certificate is valid.
 * @property DateTime $validTo The date this certificate expires.
 * @property boolean $isValidNow Whether the certificate is valid right now.
 * @property string $crlURI The URI to the CRL distribution point.
 * @property CRL $crl The crl of this certificate.
 *
 */
class X509Certificate extends Certificate {
	
	/**
	 * The certificate resource used internally for different API calls to openssl
	 * @var resource
	 */
	private $certResource = null;
	
	/**
	 * Clear text representation of the certificate in base64
	 * @var string
	 */
	private $clearText = null;
	
	/**
	 * The public key of this certificate
	 * @var PublicKey
	 */
	private $publicKey = null;
	
	/**
	 * Information returned by the openssl_x509_parse API call.
	 * @var array
	 */
	private $info = null;
	
	/**
	 * The issuer of this certificate.
	 * @var X509Certificate
	 */
	private $issuer = null;
	
	/**
	 * The date this certificate is valid from.
	 * @var DateTime
	 */
	private $validFrom = null;
	
	/**
	 * The date this certificate is to.
	 * @var DateTime
	 */
	private $validTo = null;
	
	/**
	 * The certificate revocation list of this certificate.
	 * @var CertificateRevocationList
	 */
	private $CRL;
	
	/**
	 * Holds a x509 certificate.
	 * @param string $certificate Expected to be base64 encoded and with the --- delimiters
	 */
	public function __construct($certificate) {
		if(!extension_loaded('openssl'))
			throw new OpenSSLExtensionNotLoadedException('The openssl module is not loaded.');
		$this->clearText = $certificate;
		$this->certResource = openssl_x509_read($this->clearText);
		if($this->certResource === false) {
			throw new CertificateParsingFailedException(
			'The certificate to not be parsed by openssl. Make sure it is cleartext and base64 encoded with delimiters.');
		}
		$this->info = openssl_x509_parse($this->clearText);
		{ // Validity period
			$GMT = new DateTimeZone('Europe/London');
			$this->validFrom = new DateTime(self::formatValidityString($this->info['validFrom']), $GMT);
			$this->validTo = new DateTime(self::formatValidityString($this->info['validTo']), $GMT);
		}
		$this->CRL = new CertificateRevocationList($this->crlURI);
		$this->publicKey = new PublicKey($this->certResource);
	}
	
	public function __get($name) {
		switch($name) {
			case 'publicKey':
				return $this->publicKey;
			case 'clearText':
				return $this->clearText;
			case 'compactBase64':
				return self::stripDelimitersAndLineWraps($this->clearText);
			case 'info':
				return $this->info;
			case 'commonName':
				return $this->info['subject']['CN'];
			case 'fingerprint':
				return $this->info['extensions']['subjectKeyIdentifier'];
			case 'fingerprintCA':
				$fingerprint = str_replace('keyid:', '', $this->info['extensions']['authorityKeyIdentifier']);
				$fingerprint = str_replace("\n", '', $fingerprint);
				return $fingerprint;
			case 'isSelfSigned':
				return $this->fingerprint == $this->fingerprintCA;
			case 'isCA':
				return strpos($this->info['extensions']['basicConstraints'], 'CA:TRUE') !== false;
			case 'issuer':
				return $this->issuer;
			case 'validFrom':
				return $this->validFrom;
			case 'validTo':
				return $this->validTo;
			case 'isValidNow':
				$now = new DateTime;
				return $this->validFrom < $now && $now < $this->validTo;
			case 'crlURI':
				if(preg_match('/URI:([^\\n]+)\\n/', $this->info['extensions']['crlDistributionPoints'], $matches)) {
					return $matches[1];
				}
				return null;
			case 'crl':
				return $this->CRL;
			default:
				return null;
		}
	}
	
	/**
	 * Takes base64 code and converts it into a nicely delimited string with wrapping
	 * @param string $certificate
	 * @return string
	 */
	public static function toPEM($certificate) {
		// Make sure we don't wrap something that's already wrapped
		$compact = self::stripDelimitersAndLineWraps($certificate);
		$certificateWrapped = wordwrap($compact, 64, "\r\n", true);
		$certificateDelimited = <<<End
-----BEGIN CERTIFICATE-----
$certificateWrapped
-----END CERTIFICATE-----

End;
		return $certificateDelimited;
	}
	
	/**
	 * Removes all line wraps and the delimiters from a (base64 encoded) certificate string.
	 * @param string $certificate
	 * @return string
	 */
	private static function stripDelimitersAndLineWraps($certificate) {
		$certificate = str_replace('-----BEGIN CERTIFICATE-----', '', $certificate);
		$certificate = str_replace('-----END CERTIFICATE-----', '', $certificate);
		$certificate = str_replace("\r", '', $certificate);
		$certificate = str_replace("\n", '', $certificate);
		return trim($certificate);
	}
	
	/**
	 * Formats the validity time format so it always becomes a generalized time format.
	 * It also removes the Zulu time qualifier at the end. So remember that it is in GMT.
	 * The X509 standard for date/time formats is friggin idiotic.
	 * Check it out here: http://www.ietf.org/rfc/rfc2459.txt
	 * @param string $dateTime
	 * @return string
	 */
	private static function formatValidityString($dateTime) {
		if(strlen($dateTime) > 13) {
			$dateTime = substr($dateTime, 0, 8).'T'.substr($dateTime, 8, -1);
		} else {
			$dateTime = substr($dateTime, 0, 6).'T'.substr($dateTime, 6, -1);
			if(substr($dateTime, 0, 2) >= 50)
				$dateTime = '19'.$dateTime;
			else
				$dateTime = '20'.$dateTime;
		}
		return $dateTime;
	}
	
	/**
	 * Builds a certificate chain by setting each certificates issuer.
	 * @param array $certs
	 */
	public static function buildChain(array $certs) {
		foreach($certs as $certificate) {
			foreach($certs as $ca) {
				if($certificate->fingerprintCA == $ca->fingerprint) {
					$certificate->setIssuer($ca);
					continue 2;
				}
			}
		}
	}
	
	/**
	 * Set the issuer of this certificate
	 * @param X509Certificate $issuerCertificate
	 * @throws InvalidCertificateAuthorityException
	 */
	public function setIssuer(X509Certificate $issuerCertificate) {
		if($issuerCertificate->fingerprint != $this->fingerprintCA) {
			throw new InvalidCertificateAuthorityException(
			'The issuer you are trying to set for this certificate, is not the right one.');
		}
		if(!$issuerCertificate->isCA) {
			throw new InvalidCertificateAuthorityException(
			'The issuer you are trying to set for this certificate, is not a certificate authority.');
		}
		$this->issuer = $issuerCertificate;
	}
	
	/**
	 * Can the certificate be used for the client side of an SSL connection?
	 * @var int
	 */
	const PURPOSE_SSL_CLIENT = X509_PURPOSE_SSL_CLIENT;
	/**
	 * Can the certificate be used for the server side of an SSL connection?
	 * @var int
	 */
	const PURPOSE_SSL_SERVER = X509_PURPOSE_SSL_SERVER;
	/**
	 * Can the cert be used for Netscape SSL server?
	 * @var int
	 */
	const PURPOSE_NS_SSL_SERVER = X509_PURPOSE_NS_SSL_SERVER;
	/**
	 * Can the cert be used to sign S/MIME email?
	 * @var int
	 */
	const PURPOSE_SMIME_SIGN = X509_PURPOSE_SMIME_SIGN;
	/**
	 * Can the cert be used to encrypt S/MIME email?
	 * @var int
	 */
	const PURPOSE_SMIME_ENCRYPT = X509_PURPOSE_SMIME_ENCRYPT;
	/**
	 * Can the cert be used to sign a certificate revocation list (CRL)?
	 * @var int
	 */
	const PURPOSE_CRL_SIGN = X509_PURPOSE_CRL_SIGN;
	/**
	 * Can the cert be used for Any/All purposes?
	 * @var int
	 */
	const PURPOSE_ANY = X509_PURPOSE_ANY;
	
	/**
	 * Checks the purpose of this certificate. If using PURPOSE_ANY, make sure openssl is on the PATH.
	 * A bug in PHP prevents the certificate from being checked via the api for that specific purpose.
	 * @param int $purpose The purpose to check the certificate for.
	 * @param array $caInfo List of files and directories that contain root certificates.
	 * @return boolean
	 */
	public function checkPurpose($purpose, array $caInfo) {
		if($purpose == self::PURPOSE_ANY) {
			$caPathDirsArray = array();
			$caPathFilesArray = array();
			foreach($caInfo as $caPath)
				if(is_dir($caPath))
					$caPathDirsArray[] = $caPath;
				else
					$caPathFilesArray[] = $caPath;
			
			$caPathDirs = implode(PATH_SEPARATOR, $caPathDirsArray);
			if(!empty($caPathDirs))
				$caPathDirs = " -CApath $caPathDirs";
			
			$caPathFiles = implode(PATH_SEPARATOR, $caPathFilesArray);
			if(!empty($caPathFiles))
				$caPathFiles = " -CAfile $caPathFiles";
			
			$tempCrt = tempnam(sys_get_temp_dir(), 'crt');
			file_put_contents($tempCrt, $this->clearText);
			exec("openssl verify$caPathDirs$caPathFiles -purpose any $tempCrt", $output);
			unlink($tempCrt);
			// return code of openssl is always 0, so we need to check the actual output
			return $output[0] == "$tempCrt: OK";
		}
		return openssl_x509_checkpurpose($this->certResource, $purpose, $caInfo);
	}
	
	/**
	 * Checks whether this certificate or any of it's CAs has been revoked.
	 * Automatically fetches the current CRL for the certificate.
	 * If all CRLs should be check, the chain has to be built first with X509Certificate::buildChain().
	 * @param array $caInfo List of files and directories that contain root certificates.
	 * @param boolean $checkAll Whether to check the CRL for each certificate all the way up to the root.
	 * @return boolean
	 */
	public function checkCRL(array $caInfo, $checkAll = false) {
		$caPathDirsArray = array();
		$caPathFilesArray = array();
		foreach($caInfo as $caPath)
			if(is_dir($caPath))
				$caPathDirsArray[] = $caPath;
			else
				$caPathFilesArray[] = $caPath;
		
		$crls = array();
		$crls[] = $this->crl;
		if($checkAll) {
			$certificate = $this;
			while($certificate->issuer != $certificate) {
				if($certificate->issuer == null)
					throw new CRLCheckException("Could not find the root of the certificate '$this->name'.");
				$certificate = $certificate->issuer;
				$crls[] = $certificate->crl;
			}
		}
		
		$caPathFilesArray[] = CertificateRevocationList::combineToPEM($crls);
		
		$caPathDirs = implode(PATH_SEPARATOR, $caPathDirsArray);
		if(!empty($caPathDirs))
			$caPathDirs = " -CApath $caPathDirs";
		
		$caPathFiles = implode(PATH_SEPARATOR, $caPathFilesArray);
		if(!empty($caPathFiles))
			$caPathFiles = " -CAfile $caPathFiles";
		
		$tempCrt = tempnam(sys_get_temp_dir(), 'crt');
		file_put_contents($tempCrt, $this->clearText);
		$checkParam = $checkAll?'-crl_check_all':'-crl_check';
		exec("openssl verify$caPathDirs$caPathFiles $checkParam $tempCrt", $output);
		unlink($tempCrt);
		return $output[0] == "$tempCrt: OK";
	}
	
	public function __toString() {
		return $this->clearText;
	}
	
	public function __destruct() {
		if($this->certResource)
			openssl_x509_free($this->certResource);
		$this->certResource = null;
		$this->publicKey = null;
		$this->clearText = null;
	}
}
