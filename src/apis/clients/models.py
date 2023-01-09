from datetime import datetime, timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.postgres.fields import ArrayField


class Client(models.Model):
    client_id = models.CharField(max_length=50, unique=True)
    client_secret = models.TextField()
    name = models.CharField(max_length=50, unique=True)
    response_type = models.CharField(max_length=50)
    scope = models.TextField()
    allowed_cors_origins = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    grant_type = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    redirect_uris = ArrayField(
        ArrayField(models.CharField(max_length=255)
        )
    )
    date_created = models.DateTimeField(default=datetime.utcnow)

    def validate_password(self, password: str):
        return check_password(password, self.client_secret)

    def get_default_redirect_uri(self):
        return self.redirect_uris[0]

    @staticmethod
    def create_client(payload: dict):
        return Client(
            client_id=payload['client_id'],
            client_secret=make_password(payload['client_secret']),
            name=payload['name'],
            allowed_cors_origins=payload['allowed_cors_origins'],
            response_type=payload['response_type'],
            scope=payload['scope'],
            grant_type=payload['grant_type'],
            redirect_uris=payload['redirect_uris']
        )

    @staticmethod
    def get_all_clients():
        return Client.objects

    @staticmethod
    def get_client_by_id(client_id: str):
        try:
            return Client.objects.get(client_id=client_id)
        except ObjectDoesNotExist:
            return None


class AuthorizationGrant(models.Model):
    client = models.ForeignKey(Client, on_delete=models.CASCADE)
    username = models.EmailField(max_length=100)  # NB: this username field must be stored as email
    code = models.CharField(max_length=50)
    revoked = models.BooleanField(default=False)
    response_type = models.CharField(max_length=50)
    redirect_uri = models.TextField()
    scope = models.TextField()
    grant_type = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    issued_at = models.DateTimeField(default=datetime.utcnow)
    expires_in = models.DateTimeField(default=datetime.utcnow)

    def is_valid(self, client: Client, code: str):
        """check if the authorization code is valid against the conditions below"""
        if self.client.client_id == client.client_id and not self.revoked\
                and self.code == code and datetime.utcnow() < self.expires_in:
            return True
        return False

    @staticmethod
    def create_auth_grant_code(payload: dict):
        return AuthorizationGrant(
            client=payload['client'],
            username= payload['username'],
            code=payload['code'],
            response_type=payload['response_type'],
            scope=payload['scope'],
            grant_type=payload['grant_type'],
            redirect_uri=payload['redirect_uri'],
            issued_at=datetime.now(),
            expires_in=datetime.now() + timedelta(minutes=8)
        )

    @staticmethod
    def get_auth_grant_code(code: str):
        try:
            return AuthorizationGrant.objects.get(code=code)
        except ObjectDoesNotExist:
            return None


class AccessToken(models.Model):
    client_id = models.CharField(max_length=150)
    access_token = models.TextField()
    refresh_token = models.CharField(max_length=200)
    active = models.BooleanField()
    scope = models.TextField()
    # issuer = fields.StringField(required=True, max_length=100)
    # sub = fields.StringField(required=True, max_length=100)
    # aud = fields.StringField(required=True, max_length=100)
    issued_at = models.DateTimeField(default=datetime.utcnow)
    expires_in = models.DateTimeField(default=datetime.utcnow)

    def is_valid(self, client: Client, access_token: str):
        """check if access token is valid"""
        if self.client_id == client.client_id and self.active \
                and self.access_token == access_token \
                and datetime.utcnow() < self.expires_in:
            return True
        return False

    def revoke_token(self):
        """revoke access_token"""
        self.active = False
        self.save()
        return self

    def delete_token(self):
        self.delete()

    @staticmethod
    def create_access_token(payload: dict):
        return AccessToken(
            client_id=payload['client_id'],
            access_token=payload['access_token'],
            refresh_token=payload['refresh_token'],
            scope=payload['scope'],
            expires_in=datetime.utcnow() + timedelta(seconds=payload['expires_in'])
        )

    @staticmethod
    def get_access_token(access_token: str):
        """returns an instance of access token if found else None"""
        try:
            return AccessToken.objects.get(access_token=access_token)
        except ObjectDoesNotExist:
            return None

    @staticmethod
    def get_refresh_token(refresh_token: str):
        """returns an instance of access token if found else None"""
        try:
            return AccessToken.objects.get(refresh_token=refresh_token)
        except ObjectDoesNotExist:
            return None


class WellKnownConfiguration(models.Model):
    issuer = models.URLField()
    jwks_uri = models.URLField()
    registration_endpoint = models.URLField()
    authorization_endpoint = models.URLField()
    token_endpoint = models.URLField()
    introspection_endpoint = models.URLField()
    revocation_endpoint = models.URLField()
    userinfo_endpoint = models.URLField()

    claims_parameter_supported = models.BooleanField(default=False)
    request_parameter_supported = models.BooleanField(default=False)
    request_uri_parameter_supported = models.BooleanField(default=False)

    grant_types_supported = ArrayField(
        ArrayField(models.CharField(max_length=40)
        )
    )
    scopes_supported = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    token_endpoint_auth_methods_supported = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    response_types_supported = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    token_endpoint_auth_signing_alg_values_supported = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )
    claims_supported = ArrayField(
        ArrayField(models.CharField(max_length=50)
        )
    )

    @staticmethod
    def create_well_known_configuration(payload: dict):
        return WellKnownConfiguration(
            issuer=payload['issuer'],
            jwks_uri=payload['jwks_uri'],
            registration_endpoint=payload['registration_endpoint'],
            authorization_endpoint=payload['authorization_endpoint'],
            token_endpoint=payload['token_endpoint'],
            introspection_endpoint=payload['introspection_endpoint'],
            revocation_endpoint=payload['revocation_endpoint'],
            userinfo_endpoint=payload['userinfo_endpoint'],
            claims_parameter_supported=payload['claims_parameter_supported'],
            request_parameter_supported=payload['request_parameter_supported'],
            request_uri_parameter_supported=payload['request_uri_parameter_supported'],
            grant_types_supported=payload['grant_types_supported'],
            scopes_supported=payload['scopes_supported'],
            token_endpoint_auth_methods_supported=payload['token_endpoint_auth_methods_supported'],
            response_types_supported=payload['response_types_supported'],
            token_endpoint_auth_signing_alg_values_supported=payload['token_endpoint_auth_signing_alg_values_supported'],
            claims_supported=payload['claims_supported'],
        )

    @staticmethod
    def get_well_known_config():
        return WellKnownConfiguration.objects

    @staticmethod
    def get_first_well_known_config():
        return WellKnownConfiguration.objects.first()
