<?php

namespace BWC\Component\Jwe;

abstract class Jose implements \JsonSerializable
{
    /** @var array  */
    protected $header;

    /** @var  mixed */
    protected $payload;


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

    /**
     * @return mixed data which can be serialized by <b>json_encode</b>,
     */
    public function jsonSerialize()
    {
        return array(
            'header' => $this->getHeader(),
            'payload' => $this->getPayload()
        );
    }


}