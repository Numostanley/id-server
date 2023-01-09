import base64
import json
import logging

from oauthlib.common import Request
from oauthlib.oauth2 import (
    AuthorizationCodeGrant, ResourceOwnerPasswordCredentialsGrant, BearerToken,
    IntrospectEndpoint, RefreshTokenGrant
)
from oauthlib.oauth2.rfc6749 import tokens
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from apis.utils import helpers, oauth2_helpers
from apis.utils.responses import (
    http_response_400, http_response_401, http_response_404, http_response_500, token_response
)
from apis.users.models import User
from core import settings
from .models import AuthorizationGrant, Client, WellKnownConfiguration
from .serializers import WellKnowConfigSerializer
from .validator import ClientValidator


log = logging.getLogger(__name__)


class AuthorizeAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def get(self, request, *args, **kwargs):
        query_params = request.query_params
        validate_params = helpers.validate_request_parameters(query_params, [
            'client_id', 'response_type', 'state', 'scope', 'redirect_uri', 'username'
        ])

        if validate_params:
            return validate_params

        try:
            # extract the full url path, request method, request body and request headers
            uri, http_method, body, headers = helpers.extract_request_params(request)

            # pass the values above into oauthlib.common.Request class
            oauth_request = Request(uri, http_method, body, headers)

            # instantiate client validator with the issuer
            issuer = helpers.get_issuer(request)
            validator = ClientValidator(issuer)

            # instantiate a code grant
            grant = AuthorizationCodeGrant(validator)
            grant_data = oauth2_helpers.oauth2_response_control_flow(
                grant.create_authorization_code, oauth_request)
            client = Client.get_client_by_id(oauth_request.client_id)

            # create Authorization Grant Payload
            auth_grant_payload = {
                'client': client,
                'username': User.get_user_by_email(oauth_request.username).email,
                'code': grant_data['code'],
                'response_type': oauth_request.response_type,
                'scope': oauth_request.scope,
                'grant_type': ['authorization_code'],
                'redirect_uri': oauth_request.redirect_uri
            }

            # commit to DB
            AuthorizationGrant.create_auth_grant_code(auth_grant_payload).save()
            return token_response(grant_data)
        except Exception as e:
            log.error('AuthorizeAPIView.get@Error')
            log.error(e)
            return http_response_500('Client Unauthorized!')


class TokenAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def post(self, request, *args, **kwargs):
        uri, http_method, body, headers = helpers.extract_request_params(request)
        oauth_request = Request(uri, http_method, body, headers)

        if helpers.validate_keys(body, ['grant_type']):
            return http_response_400('grant_type parameter is missing in the request body!')

        grant_type = body['grant_type']
        if grant_type not in ['authorization_code', 'password', 'refresh_token']:
            return http_response_400('Invalid grant type!')

        # instantiate client validator with the issuer
        issuer = helpers.get_issuer(request)
        validator = ClientValidator(issuer)
        token_handler = BearerToken(validator,
                                    token_generator=validator.generate_access_token,
                                    refresh_token_generator=tokens.random_token_generator,
                                    expires_in=settings.TOKEN_EXPIRY_TIME)

        if grant_type == 'authorization_code':
            validate_params = helpers.validate_request_parameters(body, [
                'client_id', 'client_secret', 'redirect_uri', 'grant_type', 'code', 'state'
            ])

            if validate_params:
                return validate_params

            auth_server = AuthorizationCodeGrant(validator)
            resp_headers, resp_body, resp_status_code = oauth2_helpers.oauth2_response_control_flow(
                auth_server.create_token_response, oauth_request, token_handler)

            return Response(
                headers=resp_headers,
                data=json.loads(resp_body),
                status=resp_status_code
            )

        elif grant_type == 'password':
            validate_params = helpers.validate_request_parameters(body, [
                'client_id', 'client_secret', 'username', 'password', 'scope', 'grant_type'
            ])

            if validate_params:
                return validate_params

            password_server = ResourceOwnerPasswordCredentialsGrant(validator)
            resp_headers, resp_body, resp_status_code = oauth2_helpers.oauth2_response_control_flow(
                password_server.create_token_response, oauth_request, token_handler)

            return Response(
                headers=resp_headers,
                data=json.loads(resp_body),
                status=resp_status_code
            )

        elif grant_type == 'refresh_token':
            validate_params = helpers.validate_request_parameters(body, [
                'client_id', 'client_secret', 'grant_type', 'refresh_token'
            ])

            if validate_params:
                return validate_params

            refresh_server = RefreshTokenGrant(validator)
            resp_headers, resp_body, resp_status_code = oauth2_helpers.oauth2_response_control_flow(
                refresh_server.create_token_response, oauth_request, token_handler)

            return Response(
                headers=resp_headers,
                data=json.loads(resp_body),
                status=resp_status_code
            )

        else:
            return http_response_401('Invalid Credentials!')


class TokenIntrospectionAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def post(self, request, *args, **kwargs):
        try:
            uri, http_method, body, headers = helpers.extract_request_params(request)

            validate_params = helpers.validate_request_parameters(body, [
                'access_token'
            ])

            if validate_params:
                return validate_params

            _, basic_auth = request.headers.get('Authorization', '').split(' ')
            decoded_auth = base64.b64decode(basic_auth).decode()
            client_id, client_secret = decoded_auth.split(':')
            client = Client.get_client_by_id(client_id)

            if not client:
                return http_response_404('Client not found!')

            if not client.validate_password(client_secret):
                return http_response_401('Invalid Client Credentials!')

            # instantiate client validator with the issuer
            issuer = helpers.get_issuer(request)
            validator = ClientValidator(issuer)
            introspection_server = IntrospectEndpoint(validator)
            resp_headers, resp_body, resp_status_code = oauth2_helpers.oauth2_response_control_flow(
                introspection_server.create_introspect_response, uri, http_method, body, headers)

            return Response(
                headers=resp_headers,
                data=json.loads(resp_body),
                status=resp_status_code
            )
        except Exception as e:
            log.error('TokenIntrospectionAPIView.post@Error')
            log.error(e)
            return http_response_500('An error occurred!')


class UserInfoAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def get(self, request, *args, **kwargs):
        pass


class WellKnowConfigAPIView(APIView):
    renderer_classes = [JSONRenderer]

    def get(self, request, *args, **kwargs):
        well_known_config = WellKnownConfiguration.get_first_well_known_config()
        serializer = WellKnowConfigSerializer(well_known_config)
        return token_response(serializer.data)
