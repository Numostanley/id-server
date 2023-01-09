import logging

import jwt

from oauthlib.oauth2.rfc6749 import errors

from apis.clients.models import AccessToken, AuthorizationGrant
from apis.users.models import User
from apis.utils.responses import *
from core import settings


log = logging.getLogger(__name__)

profile_claims = [
    'firstName', 'lastName', 'email'
]


def get_user_info(request):
    """user utilities for sign JWT"""
    user_info = {}

    if request.grant_type == 'authorization_code':
        auth_code = request.code
        auth_grant = AuthorizationGrant.get_auth_grant_code(auth_code)
        user = User.get_user_by_email(auth_grant.username)
        scopes = auth_grant.scope.split()
        for scope in scopes:
            if scope == 'openid':
                user_info.update({
                    'sub': user._id
                })
            if scope == 'profile':
                for claim in profile_claims:
                    if user.__getattribute__(claim) is not None:
                        user_info.update({
                            claim: user.__getattribute__(claim)
                        })
        return user_info
    elif request.grant_type == 'password':
        user = User.get_user_by_email(request.user)
        scopes = request.scope.split()
        for scope in scopes:
            if scope == 'openid':
                user_info.update({
                    'sub': user._id
                })
            if scope == 'profile':
                for claim in profile_claims:
                    if user.__getattribute__(claim) is not None:
                        user_info.update({
                            claim: user.__getattribute__(claim)
                        })
        return user_info
    elif request.grant_type == 'refresh_token':
        # get the refresh token
        refresh_token = AccessToken.get_refresh_token(request.refresh_token)
        # decode the access token
        decoded_token = jwt.decode(
            refresh_token.access_token,
            settings.PUBLIC_SIGNING_KEY,
            algorithms=[settings.SIGNING_ALGORITHM],
            audience=settings.CLIENTS
        )
        # retrieve the email from the decoded access token
        user = User.get_user_by_email(decoded_token['email'])
        for scope in refresh_token.scope.split():
            if scope == 'openid':
                user_info.update({
                    'sub': user._id
                })
            if scope == 'profile':
                for claim in profile_claims:
                    if user.__getattribute__(claim) is not None:
                        user_info.update({
                            claim: user.__getattribute__(claim)
                        })
        return user_info
    else:
        return user_info


def oauth2_response_control_flow(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except errors.InvalidClientError as e:
        log.error('oauth2_response_control_flow.InvalidClientError@Error')
        log.error(e)
        return token_response_401('Invalid Client!')
    except errors.UnauthorizedClientError as e:
        log.error('oauth2_response_control_flow.UnauthorizedClientError@Error')
        log.error(e)
        return token_response_401('Unauthorized Client!')
    except errors.InvalidClientIdError as e:
        log.error('oauth2_response_control_flow.InvalidClientIdError@Error')
        log.error(e)
        return token_response_401('Invalid Client ID!')
    except errors.MissingClientIdError as e:
        log.error('oauth2_response_control_flow.MissingClientIdError@Error')
        log.error(e)
        return token_response_401('Missing Client ID!')
    except errors.InvalidScopeError as e:
        log.error('oauth2_response_control_flow.InvalidScopeError@Error')
        log.error(e)
        return token_response_401('Invalid Scope!')
    except errors.InsufficientScopeError as e:
        log.error('oauth2_response_control_flow.InsufficientScopeError@Error')
        log.error(e)
        return token_response_401('Insufficient Scope!')
    except errors.MismatchingRedirectURIError as e:
        log.error('oauth2_response_control_flow.MismatchingRedirectURIError@Error')
        log.error(e)
        return token_response_401('Mismatching Redirect URI!')
    except errors.InvalidRedirectURIError as e:
        log.error('oauth2_response_control_flow.InvalidRedirectURIError@Error')
        log.error(e)
        return token_response_401('Invalid Redirect URI!')
    except errors.MissingRedirectURIError as e:
        log.error('oauth2_response_control_flow.MissingRedirectURIError@Error')
        log.error(e)
        return token_response_401('Missing Redirect URI!')
    except errors.MissingResponseTypeError as e:
        log.error('oauth2_response_control_flow.MissingResponseTypeError@Error')
        log.error(e)
        return token_response_401('Missing Response Type!')
    except errors.UnsupportedResponseTypeError as e:
        log.error('oauth2_response_control_flow.UnsupportedResponseTypeError@Error')
        log.error(e)
        return token_response_401('Unsupported Response Type!')
    except errors.TokenExpiredError as e:
        log.error('oauth2_response_control_flow.TokenExpiredError@Error')
        log.error(e)
        return token_response_401('Token Expired Error!')
    except errors.InvalidTokenError as e:
        log.error('oauth2_response_control_flow.InvalidTokenError@Error')
        log.error(e)
        return token_response_401('Invalid Token!')
    except errors.MissingTokenError as e:
        log.error('oauth2_response_control_flow.MissingTokenError@Error')
        log.error(e)
        return token_response_401('Missing Token!')
    except errors.UnsupportedTokenTypeError as e:
        log.error('oauth2_response_control_flow.UnsupportedTokenTypeError@Error')
        log.error(e)
        return token_response_401('Unsupported Token Error!')
    except errors.MissingTokenTypeError as e:
        log.error('oauth2_response_control_flow.MissingTokenTypeError@Error')
        log.error(e)
        return token_response_401('Missing Token Type!')
    except errors.InvalidGrantError as e:
        log.error('oauth2_response_control_flow.InvalidGrantError@Error')
        log.error(e)
        return token_response_401('Invalid Grant Type!')
    except errors.UnsupportedGrantTypeError as e:
        log.error('oauth2_response_control_flow.UnsupportedGrantTypeError@Error')
        log.error(e)
        return token_response_401('Unsupported Grant Type!')
    except errors.MissingCodeError as e:
        log.error('oauth2_response_control_flow.MissingCodeError@Error')
        log.error(e)
        return token_response_401('Missing Code!')
    except errors.InsecureTransportError as e:
        log.error('oauth2_response_control_flow.InsecureTransportError@Error')
        log.error(e)
        return token_response_401('Insecure Transport!')
    except errors.InvalidRequestError as e:
        log.error('oauth2_response_control_flow.InvalidRequestError@Error')
        log.error(e)
        return token_response_401('Invalid Request!')
    except errors.InvalidRequestFatalError as e:
        log.error('oauth2_response_control_flow.InvalidRequestFatalError@Error')
        log.error(e)
        return token_response_401('Invalid Fatal Request!')
    except errors.FatalClientError as e:
        log.error('oauth2_response_control_flow.FatalClientError@Error')
        log.error(e)
        return token_response_401('Fatal Client!')
    except errors.AccessDeniedError as e:
        log.error('oauth2_response_control_flow.AccessDeniedError@Error')
        log.error(e)
        return token_response_401('Access Denied!')
    except errors.ServerError as e:
        log.error('oauth2_response_control_flow.ServerError@Error')
        log.error(e)
        return token_response_401('Server Error!')
    except errors.MismatchingStateError as e:
        log.error('oauth2_response_control_flow.MismatchingStateError@Error')
        log.error(e)
        return token_response_401('Mismatching State!')
    except Exception as e:
        log.error('oauth2_response_control_flow.Generic@Error')
        log.error(e)
        return token_response_401('Generic Error!')
