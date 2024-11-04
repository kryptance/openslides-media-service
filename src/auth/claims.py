from authlib.jose.errors import InvalidClaimError
from authlib.oauth2.rfc9068.claims import JWTAccessTokenClaims


class OpenSlidesAccessTokenClaims(JWTAccessTokenClaims):
    REGISTERED_CLAIMS = JWTAccessTokenClaims.REGISTERED_CLAIMS + [
        'sid',
        'userId'
    ]

    def validate(self, **kwargs):
        super().validate(**kwargs)
        self._validate_claim_value('sid')
        self._validate_claim_value('userId')

    def validate_typ(self):
        # The resource server MUST verify that the 'typ' header value is 'at+jwt'
        # or 'application/at+jwt' and reject tokens carrying any other value.
        # -- Added jwt for keycloak compatibility
        if self.header['typ'].lower() not in ('at+jwt', 'application/at+jwt', 'jwt'):
            raise InvalidClaimError('typ')
