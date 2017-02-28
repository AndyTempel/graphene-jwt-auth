from calendar import timegm
from datetime import datetime, timedelta

import jwt
from django import forms
from django.contrib.auth import authenticate
from django.utils.translation import ugettext as _

from graphene_jwt_auth.compat import User, get_username_field
from graphene_jwt_auth.settings import api_settings

jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class JSONWebTokenForm(forms.Form):
    password = forms.CharField()

    def __init__(self, *args, **kwargs):
        super(JSONWebTokenForm, self).__init__(*args, **kwargs)

        # Dynamically add the USERNAME_FIELD to self.fields.
        self.fields[self.username_field] = forms.CharField()
        self.object = {}

    @property
    def username_field(self):
        return get_username_field()

    def clean(self):
        cleaned_data = super(JSONWebTokenForm, self).clean()
        credentials = {
            self.username_field: cleaned_data.get(self.username_field),
            'password': cleaned_data.get('password')
        }

        if all(credentials.values()):
            user = authenticate(**credentials)

            if user:
                if not user.is_active:
                    msg = _("User account is disabled.")
                    raise forms.ValidationError(msg)

                payload = jwt_payload_handler(user)

                # add token and user to cleaned_data
                return {
                    'token': jwt_encode_handler(payload),
                    'user': user
                }
            else:
                msg = _("Unable to login with provided credentials.")
                raise forms.ValidationError(msg)
        else:
            msg = _("Must include '{username_field}' and 'password'")
            msg = msg.format(username_field=self.username_field)
            raise forms.ValidationError(msg)


class VerificationBaseForm(forms.Form):
    token = forms.CharField()

    def clean(self):
        msg = _("Please define a clean method.")
        raise NotImplementedError(msg)

    @staticmethod
    def _check_payload(token):
        # Check payload valid
        try:
            payload = jwt_decode_handler(token)
        except jwt.ExpiredSignature:
            msg = _("Signature has expired.")
            raise forms.ValidationError(msg)
        except jwt.DecodeError:
            msg = _("Error decoding signature.")
            raise forms.ValidationError(msg)

        return payload

    @staticmethod
    def _check_user(payload):
        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _("Invalid payload.")
            raise forms.ValidationError(msg)

        try:
            user = User.objects.get_by_natural_key(username)
        except User.DoesNotExist:
            msg = _("User doesn't exists.")
            raise forms.ValidationError(msg)

        if not user.is_active:
            msg = _("User account is disabled.")
            raise forms.ValidationError(msg)

        return user


class VerifyJSONWebTokenForm(VerificationBaseForm):
    """
    Check the veracity of an access token.
    """

    def clean(self):
        token = self.cleaned_data.get('token')

        payload = self._check_payload(token)
        user = self._check_user(payload)

        return {
            'token': token,
            'user': user
        }


class RefreshJSONWebTokenForm(VerificationBaseForm):
    """
    Refresh an access token.
    """

    def clean(self):
        token = self.cleaned_data.get('token')

        payload = self._check_payload(token)
        user = self._check_user(payload)

        # Get and check 'orig_iat'
        orig_iat = payload.get('orig_iat')
        jti = payload.get('jti')

        if orig_iat:
            # Verify expiration
            refresh_limit = api_settings.JWT_REFRESH_EXPIRATION_DELTA

            if isinstance(refresh_limit, timedelta):
                refresh_limit = (refresh_limit.days * 24 * 3600 + refresh_limit.seconds)

            expiration_timestamp = orig_iat + int(refresh_limit)
            now_timestamp = timegm(datetime.utcnow().utctimetuple())

            if now_timestamp > expiration_timestamp:
                msg = _("Refresh has expired.")
                raise forms.ValidationError(msg)

        else:
            msg = _("orig_iat field is required.")
            raise forms.ValidationError(msg)

        new_payload = jwt_payload_handler(user)
        new_payload['orig_iat'] = orig_iat

        if jti:
            new_payload['jti'] = jti

        return {
            'token': jwt_encode_handler(new_payload),
            'user': user
        }
