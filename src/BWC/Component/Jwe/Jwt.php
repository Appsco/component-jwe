<?php

namespace BWC\Component\Jwe;

class Jwt extends Jose
{

    /**
     * @param array $header
     * @param array $payload
     */
    public function __construct(array $header = array(), array $payload = array())
    {
        $header[JwsHeader::TYPE] = 'JWT';

        parent::__construct($header, $payload);
    }


    /**
     * @return string
     */
    public function getSigningInput()
    {
        $segments = array(
                UrlSafeB64Encoder::encode(json_encode($this->getHeader())),
                UrlSafeB64Encoder::encode(json_encode($this->getPayload()))
        );

        $signing_input = implode('.', $segments);

        return $signing_input;
    }


    /**
     * @param string|null $issuer
     * @return Jwt|$this
     */
    public function setIssuer($issuer)
    {
        return $this->set(JwtClaim::ISSUER, (string)$issuer);
    }

    /**
     * @return string|null
     */
    public function getIssuer()
    {
        return $this->get(JwtClaim::ISSUER);
    }

    /**
     * @param string|null $subject
     * @return Jwt|$this
     */
    public function setSubject($subject)
    {
        return $this->set(JwtClaim::SUBJECT, (string)$subject);
    }

    /**
     * @return string|null
     */
    public function getSubject()
    {
        return $this->get(JwtClaim::SUBJECT);
    }

    /**
     * @param string|null $audience
     * @return Jwt|$this
     */
    public function setAudience($audience)
    {
        return $this->set(JwtClaim::AUDIENCE, (string)$audience);
    }

    /**
     * @return string|null
     */
    public function getAudience()
    {
        return $this->get(JwtClaim::AUDIENCE);
    }

    /**
     * @param int|\DateTime|null $expirationTime
     * @return Jwt|$this
     */
    public function setExpirationTime($expirationTime)
    {
        if ($expirationTime instanceof \DateTime) {
            $expirationTime = $expirationTime->getTimestamp();
        }
        return $this->set(JwtClaim::EXPIRATION_TIME, ($expirationTime));
    }

    /**
     * @return int|null
     */
    public function getExpirationTime()
    {
        return $this->get(JwtClaim::EXPIRATION_TIME);
    }

    /**
     * @param int|\DateTime|null $notBefore
     * @return Jwt|$this
     */
    public function setNotBefore($notBefore)
    {
        if ($notBefore instanceof \DateTime) {
            $notBefore = $notBefore->getTimestamp();
        }
        return $this->set(JwtClaim::NOT_BEFORE, ($notBefore));
    }

    /**
     * @return int|null
     */
    public function getNotBefore()
    {
        return $this->get(JwtClaim::NOT_BEFORE);
    }


    /**
     * @param int|\DateTime|null $issuedAt
     * @return Jwt|$this
     */
    public function setIssuedAt($issuedAt)
    {
        if ($issuedAt instanceof \DateTime) {
            $issuedAt = $issuedAt->getTimestamp();
        }
        return $this->set(JwtClaim::ISSUED_AT, ($issuedAt));
    }

    /**
     * @return int
     */
    public function getIssuedAt()
    {
        return intval($this->get(JwtClaim::ISSUED_AT));
    }

    /**
     * @param string $jwdId
     * @return Jwt|$this
     */
    public function setJwtId($jwdId)
    {
        return $this->set(JwtClaim::JWT_ID, $jwdId);
    }

    /**
     * @return string|null
     */
    public function getJwtId()
    {
        return $this->get(JwtClaim::JWT_ID);
    }

    /**
     * @param string $type
     * @return Jwt|$this
     */
    public function setType($type)
    {
        return $this->set(JwtClaim::TYPE, $type);
    }

    /**
     * @return string|null
     */
    public function getType()
    {
        return $this->get(JwtClaim::TYPE);
    }



} 