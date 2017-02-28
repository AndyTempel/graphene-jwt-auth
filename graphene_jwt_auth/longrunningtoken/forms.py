from django import forms
from django.utils.translation import ugettext as _

from graphene_jwt_auth.forms import VerificationBaseForm
from graphene_jwt_auth.settings import api_settings
from .models import JWTLongRunningToken

jwt_long_running_token_get_handler = api_settings.JWT_LONG_RUNNING_TOKEN_GET_HANDLER
jwt_long_running_token_set_handler = api_settings.JWT_LONG_RUNNING_TOKEN_SET_HANDLER
jwt_using_long_running_token = api_settings.JWT_USING_LONG_RUNNING_TOKEN
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class LongRunningJWTTokenForm(VerificationBaseForm):
    """
    Get long running token.
    """

    def clean(self):

        if not jwt_using_long_running_token:
            msg = _("Enable JWT_USING_LONG_RUNNING_TOKEN in your settings.")
            raise forms.ValidationError(msg)

        token = self.cleaned_data.get('token')

        # check payload and user
        payload = self._check_payload(token)
        user = self._check_user(payload)

        data = {'user': user}

        # check if long running token already exists
        long_running_token = jwt_long_running_token_get_handler(user)

        if long_running_token is None:
            long_running_token = jwt_long_running_token_set_handler(payload)

        data['token'] = long_running_token.key

        return data


class ObtainNewJWTTokenForm(forms.Form):
    """
    Get JWT Token based on long running token.
    """
    long_running_token = forms.CharField()

    def clean(self):
        if not jwt_using_long_running_token:
            msg = _("Enable JWT_USING_LONG_RUNNING_TOKEN in your settings.")
            raise forms.ValidationError(msg)

        long_running_token = self.cleaned_data.get('long_running_token')

        # check long running token on models
        try:
            token = JWTLongRunningToken.objects.get(key=long_running_token)
        except JWTLongRunningToken.DoesNotExist:
            msg = _("Long running token doesn't exists.")
            raise forms.ValidationError(msg)
        else:
            payload = jwt_payload_handler(token.user)

        return {
            'token': jwt_encode_handler(payload),
            'user': token.user
        }

