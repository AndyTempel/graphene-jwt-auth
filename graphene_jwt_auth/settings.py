"""
Code taken from django-rest-framework
https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/settings.py
"""
import datetime
from importlib import import_module

from django.conf import settings
from django.test.signals import setting_changed
from django.utils import six

DEFAULTS = {
    'JWT_ENCODE_HANDLER': 'graphene_jwt_auth.payload.jwt_encode_handler',
    'JWT_DECODE_HANDLER': 'graphene_jwt_auth.payload.jwt_decode_handler',
    'JWT_PAYLOAD_HANDLER': 'graphene_jwt_auth.payload.jwt_payload_handler',
    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
        'graphene_jwt_auth.payload.jwt_get_username_from_payload_handler',
    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_PRIVATE_KEY': None,
    'JWT_PUBLIC_KEY': None,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300),
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,
    'JWT_ALLOW_REFRESH': False,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',

    # Blacklist
    # Don't override function below `JWT_USING_BLACKLIST`
    'JWT_USING_BLACKLIST': 'graphene_jwt_auth.blacklist' in settings.INSTALLED_APPS,
    'JWT_BLACKLIST_GET_HANDLER': 'graphene_jwt_auth.blacklist.utils.jwt_blacklist_get_handler',
    'JWT_BLACKLIST_SET_HANDLER': 'graphene_jwt_auth.blacklist.utils.jwt_blacklist_set_handler',


    # Long running token
    # Don't override function below `JWT_USING_LONG_RUNNING_TOKEN`
    'JWT_USING_LONG_RUNNING_TOKEN':
        'graphene_jwt_auth.longrunningtoken' in settings.INSTALLED_APPS,
    'JWT_LONG_RUNNING_TOKEN_GET_HANDLER':
        'graphene_jwt_auth.longrunningtoken.utils.jwt_long_running_token_get_handler',
    'JWT_LONG_RUNNING_TOKEN_SET_HANDLER':
        'graphene_jwt_auth.longrunningtoken.utils.jwt_long_running_token_set_handler',
    'JWT_LONG_RUNNING_TOKEN_APP_NAME': 'app',

    # Utils
    'JWT_DELETE_LONG_RUNNING_TOKEN_WHEN_LOGOUT': False,
    'CHANGED_PASSWORD_INVALIDATED_OLD_TOKEN': False,

    # Graphene
    'QUERIES_USER_NODE':
        'graphene_jwt_auth.graphene.queries.UserNode'
}

IMPORT_STRINGS = (
    'JWT_ENCODE_HANDLER',
    'JWT_DECODE_HANDLER',
    'JWT_PAYLOAD_HANDLER',
    'JWT_PAYLOAD_GET_USERNAME_HANDLER',
    'JWT_BLACKLIST_GET_HANDLER',
    'JWT_BLACKLIST_SET_HANDLER',
    'JWT_LONG_RUNNING_TOKEN_GET_HANDLER',
    'JWT_LONG_RUNNING_TOKEN_SET_HANDLER',
    'QUERIES_USER_NODE'
)


def perform_import(val, setting_name):
    """
    If the given setting is a string import notation,
    then perform the necessary import or imports.
    """
    if val is None:
        return None
    elif isinstance(val, six.string_types):
        return import_from_string(val, setting_name)
    elif isinstance(val, (list, tuple)):
        return [import_from_string(item, setting_name) for item in val]
    return val


def import_from_string(val, setting_name):
    """
    Attempt to import a class from a string representation.
    """
    try:
        # Nod to tastypie's use of importlib.
        parts = val.split('.')
        module_path, class_name = '.'.join(parts[:-1]), parts[-1]
        module = import_module(module_path)
        return getattr(module, class_name)
    except (ImportError, AttributeError) as e:
        msg = "Could not import '%s' for API setting '%s'. %s: %s." % (
            val, setting_name, e.__class__.__name__, e)
        raise ImportError(msg)


class APISettings(object):
    """
       A settings object, that allows API settings to be accessed as properties.
       For example:
           from rest_framework.settings import api_settings
           print(api_settings.DEFAULT_RENDERER_CLASSES)
       Any setting with string import paths will be automatically resolved
       and return the class, rather than the string literal.
       """

    def __init__(self, user_settings=None, defaults=None, import_strings=None):
        if user_settings:
            self._user_settings = self.__check_user_settings(user_settings)
        self.defaults = defaults or DEFAULTS
        self.import_strings = import_strings or IMPORT_STRINGS

    @property
    def user_settings(self):
        if not hasattr(self, '_user_settings'):
            self._user_settings = getattr(settings, 'GRAPHENE_JWT_AUTH', {})
        return self._user_settings

    def __getattr__(self, attr):
        if attr not in self.defaults:
            raise AttributeError("Invalid API setting: '%s'" % attr)

        try:
            # Check if present in user settings
            val = self.user_settings[attr]
        except KeyError:
            # Fall back to defaults
            val = self.defaults[attr]

        # Coerce import strings into classes
        if attr in self.import_strings:
            val = perform_import(val, attr)

        # Cache the result
        setattr(self, attr, val)
        return val

    def __check_user_settings(self, user_settings):
        # not needed yet
        # for item in IMPORTANT_INSTALLED_APPS.items():
        #     if self.defaults[item[0]] and not item[1] in settings.INSTALLED_APPS:
        #         raise RuntimeError(
        #             "Please put '%s' on your settings.INSTALLED_APPS because you enable '%s'." %
        #             (item[1], item[0]))
        return user_settings


api_settings = APISettings(None, DEFAULTS, IMPORT_STRINGS)


def reload_api_settings(*args, **kwargs):
    global api_settings
    setting, value = kwargs['setting'], kwargs['value']
    if setting == 'GRAPHENE_JWT_AUTH':
        api_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)


setting_changed.connect(reload_api_settings)
