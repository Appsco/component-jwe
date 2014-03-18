<?php

namespace BWC\Component\Jwe;

interface EncoderInterface
{
    /**
     * @param Jose $jose
     * @param string $key
     * @param string|null $algorithm
     * @return string
     * @throws \InvalidArgumentException
     */
    public function encode(Jose $jose, $key, $algorithm = null);

    /**
     * @param string $jwtString
     * @param string|null $key
     * @return JwtReceived
     * @throws JweException
     */
    public function decode($jwtString, $key = null);

    /**
     * @param JoseReceivedInterface $jose
     * @param string $key
     * @throws JweException
     */
    public function verify(JoseReceivedInterface $jose, $key);

} 