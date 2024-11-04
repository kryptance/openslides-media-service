import requests
from authlib.jose import jwt, JsonWebKey
from authlib.jose.errors import DecodeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc9068 import JWTBearerTokenValidator
from authlib.oidc.discovery import OpenIDProviderMetadata, get_well_known_url

from .claims import OpenSlidesAccessTokenClaims


class JWTBearerOpenSlidesTokenValidator(JWTBearerTokenValidator):
    # Cache the JWKS keys to avoid fetching them repeatedly
    jwk_set = None

    def __init__(self, issuer, issuer_internal, resource_server, *args, **kwargs):
        self.issuerInternal = issuer_internal
        super().__init__(issuer, resource_server,*args, **kwargs)

    def get_jwks(self):
        if self.jwk_set is None:
            oidc_configuration = OpenIDProviderMetadata(requests.get(get_well_known_url(self.issuerInternal, True)).json())
            response = requests.get(oidc_configuration.get('jwks_uri'))
            response.raise_for_status()
            jwks_keys = response.json()
            self.jwk_set = JsonWebKey.import_key_set(jwks_keys)
        return self.jwk_set

    def authenticate_token(self, token_string):

        claims_options = {
            'iss': {'essential': True, 'validate': self.validate_iss},
            'exp': {'essential': True},
            'aud': {'essential': True, 'value': self.resource_server},
            'sub': {'essential': True},
            'client_id': {'essential': True},
            'iat': {'essential': True},
            'jti': {'essential': True},
            'auth_time': {'essential': False},
            'acr': {'essential': False},
            'amr': {'essential': False},
            'scope': {'essential': False},
            'groups': {'essential': False},
            'roles': {'essential': False},
            'entitlements': {'essential': False},
            'sid': {'essential': True},
            'userId': {'essential': True},
        }
        jwks = self.get_jwks()

        # If the JWT access token is encrypted, decrypt it using the keys and algorithms
        # that the resource server specified during registration. If encryption was
        # negotiated with the authorization server at registration time and the incoming
        # JWT access token is not encrypted, the resource server SHOULD reject it.

        # The resource server MUST validate the signature of all incoming JWT access
        # tokens according to [RFC7515] using the algorithm specified in the JWT 'alg'
        # Header Parameter. The resource server MUST reject any JWT in which the value
        # of 'alg' is 'none'. The resource server MUST use the keys provided by the
        # authorization server.
        try:
            return jwt.decode(
                token_string,
                key=jwks,
                claims_cls=OpenSlidesAccessTokenClaims,
                claims_options=claims_options,
            )
        except DecodeError:
            raise InvalidTokenError(
                realm=self.realm, extra_attributes=self.extra_attributes
            )
