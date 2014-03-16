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
        parent::__construct($header, $payload);
        $this->setType('JWT');
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
        return $this->set(Claim::ISSUER, (string)$issuer);
    }

    /**
     * @return string|null
     */
    public function getIssuer()
    {
        return $this->get(Claim::ISSUER);
    }

    /**
     * @param string|null $subject
     * @return Jwt|$this
     */
    public function setSubject($subject)
    {
        return $this->set(Claim::SUBJECT, (string)$subject);
    }

    /**
     * @return string|null
     */
    public function getSubject()
    {
        return $this->get(Claim::SUBJECT);
    }

    /**
     * @param string|null $audience
     * @return Jwt|$this
     */
    public function setAudience($audience)
    {
        return $this->set(Claim::AUDIENCE, (string)$audience);
    }

    /**
     * @return string|null
     */
    public function getAudience()
    {
        return $this->get(Claim::AUDIENCE);
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
        return $this->set(Claim::EXPIRATION_TIME, ($expirationTime));
    }

    /**
     * @return int|null
     */
    public function getExpirationTime()
    {
        return $this->get(Claim::EXPIRATION_TIME);
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
        return $this->set(Claim::NOT_BEFORE, ($notBefore));
    }

    /**
     * @return int|null
     */
    public function getNotBefore()
    {
        return $this->get(Claim::NOT_BEFORE);
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
        return $this->set(Claim::ISSUED_AT, ($issuedAt));
    }

    /**
     * @return int|null
     */
    public function getIssuedAt()
    {
        return $this->get(Claim::ISSUED_AT);
    }

    /**
     * @param string $jwdId
     * @return Jwt|$this
     */
    public function setJwtId($jwdId)
    {
        return $this->set(Claim::JWT_ID, $jwdId);
    }

    /**
     * @return string|null
     */
    public function getJwtId()
    {
        return $this->get(Claim::JWT_ID);
    }

    /**
     * @param string $type
     * @return Jwt|$this
     */
    public function setType($type)
    {
        return $this->set(Claim::TYPE, $type);
    }

    /**
     * @return string|null
     */
    public function getType()
    {
        return $this->get(Claim::TYPE);
    }


    /**
     * @param string|null $name
     * @param mixed $value
     * @return Jwt|$this
     */
    public function set($name, $value)
    {
        if ($value) {
            $this->payload[$name] = $value;
        } else {
            unset($this->payload[$name]);
        }

        return $this;
    }

    /**
     * @param string $name
     * @return mixed
     */
    public function get($name)
    {
        return @$this->payload[$name];
    }


} 