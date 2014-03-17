<?php

namespace BWC\Component\Jwe;

interface JoseReceivedInterface
{
    /**
     * @return string
     */
    public function getSigningInput();


    /**
     * @return string
     */
    public function getSignature();

    /**
     * @return string
     */
    public function getSigningAlgorithm();
}