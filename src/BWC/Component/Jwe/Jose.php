<?php

namespace BWC\Component\Jwe;

abstract class Jose
{
    /** @var array  */
    protected $header;

    /** @var  mixed */
    protected $payload;

    /** @var  string|null */
    protected $signature;


    public function __construct(array $header = array(), $payload = null)
    {
        $this->header = $header;
        $this->payload = $payload;
    }


    /**
     * @return string
     */
    abstract public function getSigningInput();



    /**
     * @param string $name
     * @param string $value
     * @return Jose|$this
     */
    public function headerSet($name, $value)
    {
        $this->header[$name] = $value;

        return $this;
    }

    /**
     * @param string $name
     * @return string
     */
    public function headerGet($name)
    {
        return @$this->header[$name];
    }

    public function headerUnset($name)
    {
        unset($this->header[$name]);
    }

    /**
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * @param mixed $payload
     */
    public function setPayload($payload)
    {
        $this->payload = $payload;
    }

    /**
     * @return mixed
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * @param null|string $signature
     */
    public function setSignature($signature)
    {
        $this->signature = $signature;
    }

    /**
     * @return null|string
     */
    public function getSignature()
    {
        return $this->signature;
    }




} 