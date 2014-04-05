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
     * @param string $class
     * @param string|null $key
     * @return Jose
     */
    public function decode($jwtString, $class = '\BWC\Component\Jwe\Jwt', $key = null);

    /**
     * @param Jose $jose
     * @param string $key
     * @throws JweException
     */
    public function verify(Jose $jose, $key);

} 