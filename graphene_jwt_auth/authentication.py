import jwt
from django.utils.dateformat import format
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _

from graphene_jwt_auth.compat import User
from graphene_jwt_auth.exceptions import AuthenticationFailed
from graphene_jwt_auth.settings import api_settings
from graphene_jwt_auth.utils import get_authorization_header

changed_password_invalidated_old_token = api_settings.CHANGED_PASSWORD_INVALIDATED_OLD_TOKEN
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER
jwt_blacklist_get_handler = api_settings.JWT_BLACKLIST_GET_HANDLER
jwt_using_blacklist = api_settings.JWT_USING_BLACKLIST


class BaseJSONWebTokenAuthentication(object):
    """
    Token based authentication using the JSON Web Token standard.
    """

    def authenticate(self, request):
        jwt_value = self.get_jwt_value(request)

        if jwt_value is None:
            return None, None

        try:
            payload = jwt_decode_handler(jwt_value)
        except jwt.ExpiredSignature:
            msg = _("Signature has expired.")
            raise AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _("Error decoding signature.")
            raise AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise AuthenticationFailed()

        # Check blacklist
        self.check_blacklist(payload)

        user = self.authenticate_credentials(payload)

        # Check if password already change invalidated all old token
        self.check_changed_password_invalidated_old_token(user, payload)

        return user, jwt_value

    def authenticate_credentials(self, payload):
        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _("Invalid payload.")
            raise AuthenticationFailed(msg)

        try:
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            msg = _("Invalid signature.")
            raise AuthenticationFailed(msg)

        if not user.is_active:
            msg = _("User account is disabled.")
            raise AuthenticationFailed(msg)

        return user

    def check_blacklist(self, payload):
        if jwt_using_blacklist:
            # will hit database once
            blacklisted = jwt_blacklist_get_handler(payload)

            if blacklisted:
                msg = _("Token has been blacklisted.")
                raise AuthenticationFailed(msg)

    def check_changed_password_invalidated_old_token(self, user, payload):
        if changed_password_invalidated_old_token and hasattr(user, 'password_last_changed'):
            # will hit database once
            # need implement `password_last_changed` on user models
            orig_iat = int(payload.get('orig_iat'))
            password_last_changed = int(format(user.password_last_changed, 'U'))

            if orig_iat < password_last_changed:
                msg = _("User must re-authenticate after changing password.")
                raise AuthenticationFailed(msg)


class JSONWebTokenAuthentication(BaseJSONWebTokenAuthentication):
    """
        Clients should authenticate by passing the token key in the "Authorization"
        HTTP header, prepended with the string specified in the setting
        `JWT_AUTH_HEADER_PREFIX`. For example:

            Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
        """
    www_authenticate_realm = 'api'

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth or smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _("Invalid Authorization header. No credentials provided.")
            raise AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _("Invalid Authorization header. Credentials string should not contain spaces.")
            raise AuthenticationFailed(msg)

        return auth[1]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(api_settings.JWT_AUTH_HEADER_PREFIX,
                                        self.www_authenticate_realm)
