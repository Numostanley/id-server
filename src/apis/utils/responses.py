from rest_framework.response import Response
from rest_framework import status


""" custom response """

def custom_response(msg: str, data=None, **kwargs):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data
        })

    return Response(
        response_data,
        status=status.HTTP_200_OK,
        **kwargs
    )


""" Token Responses """


def token_response(*args, **kwargs):
    return Response(
        *args, status=status.HTTP_200_OK, **kwargs
    )


def token_response_200(headers: dict, body, status_code: int):
    return headers, body, status_code


def token_response_401(msg: str):
    headers = {
        'Content-Type': 'application/json'
    }
    return headers, msg, 401


""" 2xx responses """

def http_response_200(msg: str, data=None, **kwargs):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data
        })

    return Response(
        response_data,
        status=status.HTTP_200_OK
    )


def http_response_201(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_201_CREATED
    )


""" 4xx responses """

def http_response_400(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_400_BAD_REQUEST
    )


def http_response_401(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_401_UNAUTHORIZED
    )


def http_response_403(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_403_FORBIDDEN
    )


def http_response_404(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_404_NOT_FOUND
    )


def http_response_409(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_409_CONFLICT
    )


def http_response_429(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_429_TOO_MANY_REQUESTS
    )


""" 5xx responses """

def http_response_500(msg: str, data=None):
    response_data = {
        'msg': msg
    }

    if data is not None:
        response_data.update({
            'data': data,
        })

    return Response(
        response_data,
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
