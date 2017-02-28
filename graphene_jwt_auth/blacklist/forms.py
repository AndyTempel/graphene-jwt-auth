from django import forms
from django.utils.translation import ugettext as _

from graphene_jwt_auth.forms import VerificationBaseForm
from graphene_jwt_auth.settings import api_settings

jwt_using_blacklist = api_settings.JWT_USING_BLACKLIST
jwt_blacklist_get_handler = api_settings.JWT_BLACKLIST_GET_HANDLER
jwt_blacklist_set_handler = api_settings.JWT_BLACKLIST_SET_HANDLER


class BlacklistJWTTokenForm(VerificationBaseForm):
    """
    Blacklist JWT Token and long running token.
    """

    def clean(self):

        if not jwt_using_blacklist:
            msg = _("Enable JWT_USING_BLACKLIST in your settings.")
            raise forms.ValidationError(msg)

        token = self.cleaned_data.get('token')

        # check payload and user
        payload = self._check_payload(token)
        user = self._check_user(payload)

        return {
            'payload': payload,
            'user': user
        }
