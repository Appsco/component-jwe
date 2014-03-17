<?php

namespace BWC\Component\Jwe;

class JwtReceived extends Jwt implements JoseReceivedInterface
{
    /** @var  string */
    protected $signingInput;

    /** @var string */
    protected $signature;


    /**
     * @param string $signingInput
     * @param string $signature
     * @param array $header
     * @param array $payload
     */
    public function __construct($signingInput, $signature, array $header = array(), array $payload = array())
    {
        parent::__construct($header, $payload);

        $this->signingInput = $signingInput;
        $this->signature = $signature;
    }


    /**
     * @return string
     */
    public function getSigningInput()
    {
        return $this->signingInput;
    }


    /**
     * @return string
     */
    public function getSignature()
    {
        return $this->signature;
    }


    /**
     * @return Jwt
     */
    public function toJwt()
    {
        return new Jwt($this->getHeader(), $this->getPayload());
    }

    /**
     * @return string
     */
    public function getSigningAlgorithm()
    {
        return $this->headerGet(JwsHeader::ALGORITHM);
    }

}