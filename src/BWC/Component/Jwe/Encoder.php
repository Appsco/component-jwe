<?php

namespace BWC\Component\Jwe;


class Encoder
{
    /** @var string */
    protected $defaultAlgorithm = Algorithm::HS256;



    public function __construct()
    {

    }



    /**
     * @param string $defaultAlgorithm
     * @throws \InvalidArgumentException
     * @return Encoder|$this
     */
    public function setDefaultAlgorithm($defaultAlgorithm)
    {
        if (!Algorithm::isValid($defaultAlgorithm)) {
            throw new \InvalidArgumentException('Invalid algorithm');
        }
        $this->defaultAlgorithm = $defaultAlgorithm;

        return $this;
    }

    /**
     * @return string
     */
    public function getDefaultAlgorithm()
    {
        return $this->defaultAlgorithm;
    }


    /**
     * @param Jose $jose
     * @param string $key
     * @param string|null $algorithm
     * @return string
     * @throws \InvalidArgumentException
     */
    public function encode(Jose $jose, $key, $algorithm = null)
    {
        $algorithm = $algorithm ? $algorithm : $this->getDefaultAlgorithm();

        if (false == Algorithm::isValid($algorithm)) {
            throw new \InvalidArgumentException('Invalid algorithm');
        }

        $jose->headerSet(JwsHeader::ALGORITHM, $algorithm);

        $signing_input = $jose->getSigningInput();

        $signature = $this->sign($signing_input, $key, $algorithm);
        $signatureB64 = UrlSafeB64Encoder::encode($signature);

        return $signing_input.'.'.$signatureB64;
    }


    /**
     * @param string $jwtString
     * @param string|null $key
     * @return JwtReceived
     * @throws JweException
     */
    public function decode($jwtString, $key = null)
    {
        if (!strpos($jwtString, '.')) {
            throw new JweException('Not a valid JWE');
        }

        $arr = explode('.', $jwtString);

        // TODO this will change with support for encryption, atm it can handle JWT only
        if (count($arr) != 3) {
            throw new JweException('Not a valid JWE');
        }

        list($headB64, $payloadB64, $cryptoB64) = $arr;

        if (null === ($header = json_decode(UrlSafeB64Encoder::decode($headB64), true))) {
            throw new JweException('Invalid JWE header');
        }

        if (null === $payload = json_decode(UrlSafeB64Encoder::decode($payloadB64), true)) {
            throw new JweException('Invalid JWE payload');
        }

        $signature = UrlSafeB64Encoder::decode($cryptoB64);

        // TODO this will change with support for encryption, atm it can handle JWT only
        $result = new JwtReceived("$headB64.$payloadB64", $signature, $header, $payload);

        if ($key) {
            $this->verify($result, $key);
        }

        return $result;
    }


    /**
     * @param JoseReceivedInterface $jose
     * @param string $key
     * @throws JweException
     */
    public function verify(JoseReceivedInterface $jose, $key)
    {
        if (!$jose->getSigningAlgorithm()) {
            throw new JweException('Algorithm not specified');
        }

        if (!$this->verifySignature($jose->getSignature(), $jose->getSigningInput(), $key, $jose->getSigningAlgorithm())) {
            throw new JweException('Invalid signature');
        }
    }



    protected function verifySignature($signature, $input, $key, $algorithm = null)
    {
        $algorithm = $algorithm ? $algorithm : $this->getDefaultAlgorithm();

        switch ($algorithm) {
            case Algorithm::HS256:
            case Algorithm::HS384:
            case Algorithm::HS512:
                return $this->sign($input, $key, $algorithm) === $signature;

            case Algorithm::RS256:
                return openssl_verify($input, $signature, $key, 'sha256') === 1;

            case Algorithm::RS384:
                return @openssl_verify($input, $signature, $key, 'sha384') === 1;

            case Algorithm::RS512:
                return @openssl_verify($input, $signature, $key, 'sha512') === 1;

            default:
                throw new JweException('Unsupported or invalid signing algorithm');
        }
    }

    private function sign($input, $key, $algorithm = 'HS256')
    {
        $algorithm = $algorithm ? $algorithm : $this->getDefaultAlgorithm();

        switch ($algorithm) {
            case Algorithm::HS256:
                return hash_hmac('sha256', $input, $key, true);

            case Algorithm::HS384:
                return hash_hmac('sha384', $input, $key, true);

            case Algorithm::HS512:
                return hash_hmac('sha512', $input, $key, true);

            case Algorithm::RS256:
                return $this->generateRSASignature($input, $key, 'sha256');

            case Algorithm::RS384:
                return $this->generateRSASignature($input, $key, 'sha384');

            case Algorithm::RS512:
                return $this->generateRSASignature($input, $key, 'sha512');

            default:
                throw new JweException('Unsupported or invalid signing algorithm');
        }
    }

    private function generateRSASignature($input, $key, $algorithm)
    {
        if (!openssl_sign($input, $signature, $key, $algorithm)) {
            throw new JweException('Unable to sign data');
        }

        return $signature;
    }


}
