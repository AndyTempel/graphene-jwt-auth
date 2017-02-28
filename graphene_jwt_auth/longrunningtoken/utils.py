from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils.timezone import utc
from django.utils.translation import ugettext as _

from graphene_jwt_auth.compat import User
from graphene_jwt_auth.settings import api_settings
from .models import JWTLongRunningToken

jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


def jwt_long_running_token_get_handler(user):
    """
    Default implementation to check if a long running token exists.
    Should return long running token or None.
    """

    try:
        token = JWTLongRunningToken.objects.get(user=user)
    except JWTLongRunningToken.DoesNotExist:
        return None
    else:
        return token


def jwt_long_running_token_set_handler(payload):
    """
    Default implementation that create long running token.
    Should return a long running token or None.
    """

    # get username
    username = jwt_get_username_from_payload(payload)

    user = User.objects.get_by_natural_key(username)

    # Get and check 'orig_iat'
    orig_iat = payload.get('orig_iat')

    if orig_iat:
        # check refresh_limit
        refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA
        if isinstance(refresh_limit, timedelta):
            refresh_limit = (refresh_limit.days * 24 * 3600 + refresh_limit.seconds)
        expiration_timestamp = orig_iat + int(refresh_limit)
    else:
        msg = _("orig_iat field is required.")
        raise ValidationError(msg)

    try:
        data = {
            'user': user,
            'app': api_settings.JWT_LONG_RUNNING_TOKEN_APP_NAME,
            'expires': datetime.fromtimestamp(expiration_timestamp, tz=utc)
        }
        token = JWTLongRunningToken.objects.create(**data)
    except(TypeError, IntegrityError, Exception):
        return None
    else:
        return token
