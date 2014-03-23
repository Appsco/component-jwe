<?php

namespace BWC\Component\Jwe\Test;

use BWC\Component\Jwe\Algorithm;
use BWC\Component\Jwe\Encoder;
use BWC\Component\Jwe\Jose;
use BWC\Component\Jwe\JweException;
use BWC\Component\Jwe\Jwt;

class EncoderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function shouldConstruct()
    {
        new Encoder();
    }

    /**
     * @test
     */
    public function shouldHaveDefaultAlgorithmHS256()
    {
        $encoder = new Encoder();
        $this->assertEquals(Algorithm::HS256, $encoder->getDefaultAlgorithm());
    }

    /**
     * @test
     */
    public function shouldSetDefaultAlgorithm()
    {
        $encoder = new Encoder();
        $encoder->setDefaultAlgorithm(Algorithm::HS512);
        $this->assertEquals(Algorithm::HS512, $encoder->getDefaultAlgorithm());
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid algorithm
     */
    public function shouldThrowWhenSetInvalidDefaultAlgorithm()
    {
        $encoder = new Encoder();
        $encoder->setDefaultAlgorithm('foo');
    }


    public function shouldEncodeProvider()
    {
        $jwt = new Jwt(array('h1'=>1, 'h2'=>2), array('pl1'=>1, 'pl2'=>2));
        $key = 'secret_key';
        return array(
            array($jwt, $key, Algorithm::HS256, 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJwbDEiOjEsInBsMiI6Mn0.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o'),
            array($jwt, $key, Algorithm::HS384, 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMzg0In0.eyJwbDEiOjEsInBsMiI6Mn0.G8L-o74casYsQhA7r7jvkC8hImMeBw_pVhvamjBwRo1HMgbQ8x1nkPd_SkFuGFLD'),
            array($jwt, $key, Algorithm::HS512, 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTNTEyIn0.eyJwbDEiOjEsInBsMiI6Mn0.s7KZrQaYd4WEVxNihj0i47TpXht9G6IzQ9MUP0ebNsr9C2zinwxqIjb1WGFUQtWHEVoTZeO5LsqxRexxWFrUyQ')
        );
    }

    /**
     * @test
     * @dataProvider shouldEncodeProvider
     */
    public function shouldEncode(Jose $jwt, $key, $algorithm, $expectedToken)
    {
        $encoder = new Encoder();
        $token = $encoder->encode($jwt, $key, $algorithm);

        $this->assertEquals($expectedToken, $token);
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid algorithm
     */
    public function shouldThrowWhenEncodeWithInvalidAlgorithm()
    {
        $jwt = new Jwt();
        $key = 'secret_key';

        $encoder = new Encoder();
        $encoder->encode($jwt, $key, 'foo');
    }


    /**
     * @test
     */
    public function shouldDecode()
    {
        $token = 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJwbDEiOjEsInBsMiI6Mn0.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o';
        $expectedHeader = array('h1'=>1, 'h2'=>2);
        $expectedPayload = array('pl1'=>1, 'pl2'=>2);

        $encoder = new Encoder();
        $jose = $encoder->decode($token);

        $this->assertArrayHasKey('h1', $jose->getHeader());
        $this->assertArrayHasKey('h2', $jose->getHeader());
        $this->assertEquals($expectedHeader['h1'], $jose->getHeader()['h1']);
        $this->assertEquals($expectedHeader['h2'], $jose->getHeader()['h2']);

        $this->assertEquals($expectedPayload, $jose->getPayload());
    }

    public function shouldThrowOnDecodeMalformedTokenProvider()
    {
        return array(
            array('foo_bar'),
            array('foo.bar'),
            array('foo.bar.baz.spike'),
        );
    }

    /**
     * @test
     * @dataProvider shouldThrowOnDecodeMalformedTokenProvider
     * @expectedException \BWC\Component\Jwe\JweException
     * @expectedExceptionMessage Not a valid JWE
     */
    public function shouldThrowOnDecodeMalformedToken($token)
    {
        $encoder = new Encoder();
        $encoder->decode($token);
    }

    /**
     * @test
     * @expectedException \BWC\Component\Jwe\JweException
     * @expectedExceptionMessage Invalid JWE header
     */
    public function shouldThrowOnInvalidHeader()
    {
        $token = 'peraMikaLaza.eyJwbDEiOjEsInBsMiI6Mn0.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o';
        //$token = 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJwbDEiOjEsInBsMiI6Mn0.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o';
        $encoder = new Encoder();
        $encoder->decode($token);
    }

    /**
     * @test
     * @expectedException \BWC\Component\Jwe\JweException
     * @expectedExceptionMessage Invalid JWE payload
     */
    public function shouldThrowOnInvalidPayload()
    {
        $token = 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.PeraMikaLaza.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o';
        $encoder = new Encoder();
        $encoder->decode($token);
    }

    /**
     * @test
     */
    public function shouldDecodeAndVerify()
    {
        $key = 'secret_key';
        $token = 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJwbDEiOjEsInBsMiI6Mn0.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o';
        $expectedHeader = array('h1'=>1, 'h2'=>2);
        $expectedPayload = array('pl1'=>1, 'pl2'=>2);

        $encoder = new Encoder();
        $jose = $encoder->decode($token, $key);

        $this->assertArrayHasKey('h1', $jose->getHeader());
        $this->assertArrayHasKey('h2', $jose->getHeader());
        $this->assertEquals($expectedHeader['h1'], $jose->getHeader()['h1']);
        $this->assertEquals($expectedHeader['h2'], $jose->getHeader()['h2']);

        $this->assertEquals($expectedPayload, $jose->getPayload());
    }

    /**
     * @test
     * @expectedException \BWC\Component\Jwe\JweException
     * @expectedExceptionMessage Invalid signature
     */
    public function shouldThrowIfInvalidSignatureOnDecodeAndVerify()
    {
        $key = 'secret_key-alt';
        $token = 'eyJoMSI6MSwiaDIiOjIsInR5cCI6IkpXVCIsImFsZyI6IkhTMjU2In0.eyJwbDEiOjEsInBsMiI6Mn0.RASIJrI-LX98YBIQDw3g9sXnNPrCdVBr02YyO1Z4i0o';
        $expectedHeader = array('h1'=>1, 'h2'=>2);
        $expectedPayload = array('pl1'=>1, 'pl2'=>2);

        $encoder = new Encoder();
        $jose = $encoder->decode($token, $key);

        $this->assertArrayHasKey('h1', $jose->getHeader());
        $this->assertArrayHasKey('h2', $jose->getHeader());
        $this->assertEquals($expectedHeader['h1'], $jose->getHeader()['h1']);
        $this->assertEquals($expectedHeader['h2'], $jose->getHeader()['h2']);

        $this->assertEquals($expectedPayload, $jose->getPayload());
    }

} 