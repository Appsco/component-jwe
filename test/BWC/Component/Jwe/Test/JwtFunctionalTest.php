<?php

namespace BWC\Component\Jwe\Test;


use BWC\Component\Jwe\Encoder;
use BWC\Component\Jwe\Jwt;

class JwtFunctionalTest extends \PHPUnit_Framework_TestCase
{

    public function testEncodeDecode01()
    {
        $jwt = new Jwt();
        $jwt
                ->setIssuedAt($expectedIssuedAt = time())
                ->setIssuer($expectedIssuer = 'BWC')
                ->setSubject($expectedSubject = 'subject')
                ->setAudience($expectedAudience = 'audience')
                ->setExpirationTime($expectedExpirationTime = $expectedIssuedAt + 120)
                ->setNotBefore($expectedNotBefore = $expectedIssuedAt - 120)
                ->setJwtId($expectedId = mt_rand(10000, 999999))
                ->set('email', $expectedEmail = 'mike@example.com')
        ;

        $encoder = new Encoder();
        $key = 's466j5424G1eLsSBT45I2p94t';

        $token = $encoder->encode($jwt, $key);

        $jwt = $encoder->decode($token, $key);

        $this->assertEquals($expectedIssuedAt, $jwt->getIssuedAt());
        $this->assertEquals($expectedIssuer, $jwt->getIssuer());

        $this->assertEquals($expectedSubject, $jwt->getSubject());
        $this->assertEquals($expectedAudience, $jwt->getAudience());
        $this->assertEquals($expectedExpirationTime, $jwt->getExpirationTime());
        $this->assertEquals($expectedNotBefore, $jwt->getNotBefore());
        $this->assertEquals($expectedId, $jwt->getJwtId());
        $this->assertEquals($expectedEmail, $jwt->get('email'));
    }

}
