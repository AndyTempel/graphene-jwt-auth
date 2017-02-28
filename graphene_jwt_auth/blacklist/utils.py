from datetime import datetime

from django.db import IntegrityError
from django.utils.timezone import now, utc

from .models import JWTBlacklistToken


def jwt_blacklist_get_handler(payload):
    """
    Default implementation to check if a blacklisted jwt token exists.
    Should return a black listed token or None.
    """
    jti = payload.get('jti')

    try:
        token = JWTBlacklistToken.objects.get(jti=jti)
    except JWTBlacklistToken.DoesNotExist:
        return None
    else:
        return token


def jwt_blacklist_set_handler(payload):
    """
    Default implementation that blacklists a jwt token.
    Should return a black listed token or None.
    """
    try:
        data = {
            'jti': payload.get('jti'),
            'created': now(),
            'expires': datetime.fromtimestamp(payload.get('exp'), tz=utc)
        }
        token = JWTBlacklistToken.objects.create(**data)
    except (TypeError, IntegrityError, Exception):
        return None
    else:
        return token
