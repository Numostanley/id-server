"""
this module contains utilities that are used across the codebase
"""
from apis.clients.models import Client
from apis.users.models import User
from apis.utils.responses import http_response_400, http_response_401, http_response_404


def extract_request_params(request) -> tuple:
    return request.build_absolute_uri(), request.method, request.data, request.headers


def validate_keys(query_params: dict, required_keys: list | tuple) -> list:
    # extract keys from payload
    query_params_keys = list(query_params.keys())

    # check if extracted keys is present in required_keys
    missing_keys = []
    for key in required_keys:
        if key not in query_params_keys:
            missing_keys.append(key)

    return missing_keys


def validate_keys_values(payload: dict) -> list:
    missing_key_values = []

    for key in payload:
        if not payload[key]:
            missing_key_values.append(key)
    return missing_key_values


def validate_scopes(scopes: list, allowed_scopes: list) -> bool:
    """
    validate scopes specified in the request parameters against scopes defined for
    the client.
    :returns: True if all scopes defined in scopes are found in the allowed_scopes,
        False if at least one scope found in scopes is not in the allowed_scopes
    """
    res = []
    for i in scopes:
        if i in allowed_scopes:
            res.append(True)
        else:
            res.append(False)
    return False if False in res else True


def get_issuer(request):
    """
    returns the originating host i.e SERVER NAME and SERVER PORT
    """
    return request.get_host()


def validate_request_parameters(payload: dict, keys: list):
    missing_keys = validate_keys(payload, keys)

    if missing_keys:
        return http_response_400(
            f"The following key(s) are missing in the request parameters: {missing_keys}"
        )

    # check for missing keys' values
    missing_keys_values = validate_keys_values(payload)

    if missing_keys_values:
        return http_response_400(
            f"Value(s) are not specified for the following request parameters: {missing_keys_values}"
        )

    if 'client_id' in payload:
        client = Client.get_client_by_id(payload['client_id'])
        if not client:
            return http_response_404('Client not found!')
        if 'client_secret' in payload:
            if not client.validate_password(payload['client_secret']):
                return http_response_401('Invalid Client Credentials!')

    if 'username' and 'password' in payload:
        user = User.get_user_by_email(payload['username'])
        if not user:
            return http_response_404('User not found!')
        if not user.validate_password(payload['password']):
            return http_response_401('Invalid user credentials!')

    pass
