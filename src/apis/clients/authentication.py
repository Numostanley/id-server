import base64
import binascii

from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions

from apis.clients.models import Client


class ClientBasicAuthentication(BaseAuthentication):
    www_authenticate_realm = 'api'

    def authenticate(self, request):
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'basic':
            return None

        if len(auth) == 1:
            msg = 'Invalid basic header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid basic header. Credentials string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            try:
                auth_decoded = base64.b64decode(auth[1]).decode('utf-8')
            except UnicodeDecodeError:
                auth_decoded = base64.b64decode(auth[1]).decode('latin-1')
            auth_parts = auth_decoded.partition(':')
        except (TypeError, UnicodeDecodeError, binascii.Error):
            msg = 'Invalid basic header. Credentials not correctly base64 encoded.'
            raise exceptions.AuthenticationFailed(msg)

        userid, password = auth_parts[0], auth_parts[2]
        return self.authenticate_credentials(userid, password, request)

    def authenticate_header(self, request):
        print('Basic realm="%s"' % self.www_authenticate_realm)
        return 'Basic realm="%s"' % self.www_authenticate_realm

    def authenticate_credentials(self, userid, password, request=None):
        client = Client.get_client_by_id(userid)
        if client.validate_password(password):
            return None
        return client, None
