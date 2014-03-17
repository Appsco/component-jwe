<?php

namespace BWC\Component\Jwe;

final class JwsHeader
{
    /**
     * Type of the object
     */
    const TYPE = 'typ';

    /**
     * Structural information
     */
    const CONTENT_TYPE = 'cty';

    /**
     * cryptographic algorithm used
     */
    const ALGORITHM = 'alg';

    /**
     * URI that refers to a resource for a set of JSON-encoded public keys
     */
    const JWK_SET_URL = 'jku';

    /**
     * public key that corresponds to the key used to digitally sign the JWS
     */
    const JSON_WEB_KEY = 'jwk';

    /**
     * hint indicating which key was used to secure the JWS
     */
    const KEY_ID = 'kid';

    /**
     * URI that refers to a resource for the X.509 public key certificate or certificate chain
     * corresponding to the key used to digitally sign the JWS
     */
    const X509_URL = 'x5u';

    /**
     * X.509 public key certificate or certificate chain corresponding to the key used to digitally sign the JWS
     */
    const X509_CERTIFICATE_CHAIN = 'x5c';

    /**
     * base64url encoded SHA-1 thumbprint (digest) of the DER encoding of the X.509 certificate corresponding to
     * the key used to digitally sign the JWS
     */
    const X509_THUMBPRINT = 'x5t';

    /**
     * extensions being used that MUST be understood and processed
     */
    const CRITICAL = 'crit';



    private function __construct() { }
} 