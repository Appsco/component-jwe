<?php

namespace BWC\Component\Jwe;

final class Claim
{
    const ISSUER = 'iss';

    const SUBJECT = 'sub';

    const AUDIENCE = 'aud';

    const EXPIRATION_TIME = 'exp';

    const NOT_BEFORE = 'nbf';

    const ISSUED_AT = 'iat';

    const JWT_ID = 'jti';

    const TYPE = 'typ';



    private function __construct() { }
} 