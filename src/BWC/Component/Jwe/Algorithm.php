<?php

namespace BWC\Component\Jwe;

/**
 * @link http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-23#section-3.1
 */
final class Algorithm
{
    /**
     * HMAC using SHA-256
     */
    const HS256 = 'HS256';

    /**
     * HMAC using SHA-384
     */
    const HS384 = 'HS384';

    /**
     * HMAC using SHA-512
     */
    const HS512 = 'HS512';

    /**
     * RSASSA-PKCS-v1_5 using SHA-256
     */
    const RS256 = 'RS256';

    /**
     * RSASSA-PKCS-v1_5 using SHA-384
     */
    const RS384 = 'RS384';

    /**
     * RSASSA-PKCS-v1_5 using SHA-512
     */
    const RS512 = 'RS512';

    /**
     * ECDSA using P-256 and SHA-256
     */
    const ES256 = 'ES256';

    /**
     * ECDSA using P-384 and SHA-384
     */
    const ES384 = 'ES384';

    /**
     * ECDSA using P-521 and SHA-512
     */
    const ES512 = 'ES512';

    /**
     * RSASSA-PSS using SHA-256 and MGF1 with SHA-256
     */
    const PS256 = 'PS256';

    /**
     * RSASSA-PSS using SHA-384 and MGF1 with SHA-384
     */
    const PS384 = 'PS384';

    /**
     * RSASSA-PSS using SHA-512 and MGF1 with SHA-512
     */
    const PS512 = 'PS512';

    /**
     * No digital signature or MAC performed
     */
    const NONE = 'none';


    /**
     * @param string $algorithm
     * @return bool
     */
    static public function isValid($algorithm)
    {
        return in_array($algorithm, self::$validAlgorithms);
    }



    static private $validAlgorithms = array(
            self::HS256, self::HS384, self::HS512,
            self::RS256, self::RS384, self::RS512,
            self::ES256, self::ES384, self::ES512,
            self::PS256, self::PS384, self::PS512
    );

    private function __construct() { }
} 