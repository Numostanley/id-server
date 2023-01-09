from rest_framework import serializers


class WellKnowConfigSerializer(serializers.Serializer):
    issuer = serializers.URLField()
    jwks_uri = serializers.URLField()
    registration_endpoint = serializers.URLField()
    authorization_endpoint = serializers.URLField()
    token_endpoint = serializers.URLField()
    introspection_endpoint = serializers.URLField()
    revocation_endpoint = serializers.URLField()
    userinfo_endpoint = serializers.URLField()

    claims_parameter_supported = serializers.BooleanField()
    request_parameter_supported = serializers.BooleanField()
    request_uri_parameter_supported = serializers.BooleanField()

    grant_types_supported = serializers.ListSerializer(
        child=serializers.CharField()
    )
    scopes_supported = serializers.ListSerializer(
        child=serializers.CharField()
    )
    token_endpoint_auth_methods_supported = serializers.ListSerializer(
        child=serializers.CharField()
    )
    response_types_supported = serializers.ListSerializer(
        child=serializers.CharField()
    )
    token_endpoint_auth_signing_alg_values_supported = serializers.ListSerializer(
        child=serializers.CharField()
    )
    claims_supported = serializers.ListSerializer(
        child=serializers.CharField()
    )
