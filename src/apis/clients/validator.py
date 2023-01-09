import logging
import uuid

from datetime import datetime, timedelta

import jwt

from oauthlib.openid import RequestValidator

from apis.users.models import User
from apis.utils import helpers
from apis.utils import oauth2_helpers
from core import settings
from .models import AccessToken, AuthorizationGrant, Client


log = logging.getLogger(__name__)


class ClientValidator(RequestValidator):

    def __init__(self, issuer):
        self.private_secret = settings.SIGNING_KEY
        self.public_secret = settings.PUBLIC_SIGNING_KEY
        self.issuer = issuer

    def generate_access_token(self, request):
        payload = {
            "ref": str(uuid.uuid4()),
            "aud": request.client_id,
            "iat": datetime.utcnow(),
            "iss": self.issuer,
            "exp": datetime.utcnow() + timedelta(seconds=settings.TOKEN_EXPIRY_TIME),
            **oauth2_helpers.get_user_info(request)
        }
        if request.grant_type == 'authorization_code':
            auth_code = request.code
            auth_grant_scopes = AuthorizationGrant.get_auth_grant_code(auth_code)
            payload.update({
                "scope": auth_grant_scopes.scope
            })
            token = jwt.encode(payload,
                               self.private_secret,
                               algorithm=settings.SIGNING_ALGORITHM)
            return token
        elif request.grant_type == 'password':
            payload.update({
                "scope": request.scope.split(" ")
            })
            token = jwt.encode(payload,
                               self.private_secret,
                               algorithm=settings.SIGNING_ALGORITHM)
            return token
        elif request.grant_type == 'refresh_token':
            refresh_token = AccessToken.get_refresh_token(request.refresh_token)
            payload.update({
                "scope": refresh_token.scope
            })
            token = jwt.encode(payload,
                               self.private_secret,
                               algorithm=settings.SIGNING_ALGORITHM)
            return token
        else:
            client = Client.get_client_by_id(request.client_id)
            payload.update({
                "scope": client.scopes
            })
            token = jwt.encode(payload,
                               self.private_secret,
                               algorithm=settings.SIGNING_ALGORITHM)
            return token

    def validate_client_id(self, client_id, request, *args, **kwargs):
        try:
            client = Client.get_client_by_id(client_id)
            return True if client else False
        except Exception as e:
            log.error('ClientValidator.validate_client_id@Error')
            log.error(e)
            return False

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        try:
            client = Client.get_client_by_id(client_id)
            return redirect_uri in client.redirect_uris
        except Exception as e:
            log.error('ClientValidator.validate_redirect_uri@Error')
            log.error(e)
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        try:
            client_instance = Client.get_client_by_id(client_id)
            return helpers.validate_scopes(
                request.scope.split(" "), client_instance.scope.split()
            )
        except Exception as e:
            log.error('ClientValidator.validate_scopes@Error')
            log.error(e)
            return False

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        try:
            client = Client.get_client_by_id(client_id)
            return response_type == client.response_type
        except Exception as e:
            log.error('ClientValidator.validate_response_type@Error')
            log.error(e)
            return False

    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        pass

    # Token request

    def client_authentication_required(self, request, *args, **kwargs):
        # Check if the client provided authentication information that needs to
        # be validated, e.g. HTTP Basic auth
        return True

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        try:
            client_instance = Client.get_client_by_id(request.client_id)
            if client_instance.validate_password(request.client_secret):
                request.client = client_instance
                return True
            return False
        except Exception as e:
            log.error('ClientValidator.authenticate_client@Error')
            log.error(e)
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # The client_id must match an existing public (non-confidential) client
        try:
            client_instance = Client.get_client_by_id(client_id)
            if client_instance:
                request.client = client_instance
                return True
            return False
        except Exception as e:
            log.error('ClientValidator.authenticate_client_id@Error')
            log.error(e)
            return False

    def get_authorization_code_scopes(self, client_id, code, redirect_uri, request):
        try:
            auth_grant_code = AuthorizationGrant.get_auth_grant_code(code)
            return auth_grant_code.scope.split()
        except Exception as e:
            log.error('ClientValidator.get_authorization_code_scopes@Error')
            log.error(e)
            return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes
        # and user to request.scopes and request.user.
        try:
            auth_grant_code = AuthorizationGrant.get_auth_grant_code(code)
            client = Client.get_client_by_id(client_id)
            return auth_grant_code.is_valid(client, code)
        except Exception as e:
            log.error('ClientValidator.validate_code@Error')
            log.error(e)
            return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        try:
            auth_grant_code = AuthorizationGrant.get_auth_grant_code(code)
            return auth_grant_code.redirect_uri == redirect_uri
        except Exception as e:
            log.error('ClientValidator.confirm_redirect_uri@Error')
            log.error(e)
            return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        try:
            client_instance = Client.get_client_by_id(client_id)
            return grant_type in client_instance.grant_type
        except Exception as e:
            log.error('ClientValidator.validate_grant_type@Error')
            log.error(e)
            return False

    def validate_user(self, username, password, client, request, *args, **kwargs):
        # NB: username points to the email field of the User document
        # validate username and password if grant_type is password
        try:
            client_instance = Client.get_client_by_id(request.client_id)
            # NB: the username here points to the email field of the User document
            # since username is not used for the application, email is used
            user = User.get_user_by_email(username)
            if user.validate_password(password):
                request.user = username
                # set request.client to client object for Resource Owner Password Credentials Grant
                request.client = client_instance
                return True
            return False
        except Exception as e:
            log.error('ClientValidator.validate_user@Error')
            log.error(e)
            return False

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        client = Client.get_client_by_id(request.client_id)

        # check if access_token exists
        refresh_token = AccessToken.get_refresh_token(request.refresh_token)

        # create a new access_token and refresh_token
        payload = {
            'client_id': client.client_id,
            'access_token': token['access_token'],
            'refresh_token': token['refresh_token'],
            'token_type': token['token_type'],
            'expires_in': token['expires_in']
        }

        if request.grant_type == 'authorization_code':
            auth_grant_code = request.code
            auth_grant = AuthorizationGrant.get_auth_grant_code(auth_grant_code)
            scope = auth_grant.scope
            payload.update({
                'scope': scope
            })
            # create new access_token and save to db
            AccessToken.create_access_token(payload).save()

        elif request.grant_type == 'password':
            payload.update({
                'scope': request.scope
            })
            # create new access_token and save to db
            AccessToken.create_access_token(payload).save()

        elif request.grant_type == 'refresh_token':
            # if access_token exists and not revoked and the grant_type is refresh_token,
            # update the fields below

            # update the payload with the token former scope
            payload.update({
                'scope': refresh_token.scope
            })

            # create new access_token and save to db
            AccessToken.create_access_token(payload).save()
            # delete the old refresh token
            refresh_token.delete()
        else:
            pass
        return client.get_default_redirect_uri

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        auth_grant_code = AuthorizationGrant.objects.get(code=code)
        auth_grant_code.delete()

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        pass

    # Token refresh request

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        # validate the refresh token sent by the client
        token = AccessToken.get_refresh_token(refresh_token)
        client_instance = Client.get_client_by_id(request.client_id)
        try:
            if not token or not token.active or not token.is_valid(
                    client_instance, token.access_token):
                return False
            return True
        except Exception as e:
            log.error('ClientValidator.validate_refresh_token@Error')
            log.error(e)
            return False

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        pass

    # Token introspection

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        # check if the token passed to the authorization server from the
        # resource server is valid
        try:
            valid_token_type_hint = ['access_token', 'refresh_token']
            if token_type_hint not in valid_token_type_hint:
                return None

            client = Client.get_client_by_id(request.client_id)
            if not client.validate_password(request.client_secret):
                return None

            if not AccessToken.get_access_token(token).is_valid(client, token):
                return None

            decode_token = jwt.decode(
                token, self.public_secret,
                algorithms=[settings.SIGNING_ALGORITHM], audience=settings.CLIENTS
            )
            return decode_token
        except Exception as e:
            log.error('ClientValidator.introspect_token@Error')
            log.error(e)
            return None

    # OpenID Connect

    def get_userinfo_claims(self, request) -> None:
        pass
