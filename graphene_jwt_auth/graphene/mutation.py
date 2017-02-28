import graphene
from django.contrib.auth.signals import user_logged_in
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext as _
from graphene import relay

from graphene_jwt_auth.blacklist.forms import BlacklistJWTTokenForm
from graphene_jwt_auth.exceptions import AuthenticationFailed
from graphene_jwt_auth.forms import (
    JSONWebTokenForm,
    RefreshJSONWebTokenForm,
    VerifyJSONWebTokenForm
)
from graphene_jwt_auth.longrunningtoken.forms import LongRunningJWTTokenForm, ObtainNewJWTTokenForm
from graphene_jwt_auth.settings import api_settings
from graphene_jwt_auth.utils.core import get_token
from .permissions import IsAuthenticated
from .relay.mutation import ClientIDMutation

user_node = api_settings.QUERIES_USER_NODE
jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_using_blacklist = api_settings.JWT_USING_BLACKLIST
jwt_blacklist_set_handler = api_settings.JWT_BLACKLIST_SET_HANDLER
jwt_blacklist_get_handler = api_settings.JWT_BLACKLIST_GET_HANDLER
jwt_using_long_running_token = api_settings.JWT_USING_LONG_RUNNING_TOKEN
jwt_long_running_token_get_handler = api_settings.JWT_LONG_RUNNING_TOKEN_GET_HANDLER
jwt_delete_long_running_token_when_logout = api_settings.JWT_DELETE_LONG_RUNNING_TOKEN_WHEN_LOGOUT


class Login(relay.ClientIDMutation):

    class Input:
        email = graphene.String(required=True)
        password = graphene.String(required=True)

    token = graphene.String()
    user = graphene.Field(user_node)

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        data = {
            'email': input.get('email'),
            'password': input.get('password')
        }

        form = JSONWebTokenForm(data)

        if not form.is_valid():
            raise ValidationError(form.errors)

        user = form.cleaned_data.get('user')
        user_logged_in.send(sender=user.__class__, request=context, user=user)
        return Login(**form.cleaned_data)


class RefreshToken(ClientIDMutation):
    permission_classes = (IsAuthenticated,)

    token = graphene.String()
    user = graphene.Field(user_node)

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        token = get_token(context)

        if not token:
            msg = _("Authorization header not found.")
            raise AuthenticationFailed(msg)

        form = RefreshJSONWebTokenForm({"token": token})

        if not form.is_valid():
            raise ValidationError(form.errors)

        return RefreshToken(**form.cleaned_data)


class VerifyToken(ClientIDMutation):

    class Input:
        token = graphene.String(required=True)

    token = graphene.String()
    user = graphene.Field(user_node)

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        token = input.get('token')

        form = VerifyJSONWebTokenForm({'token': token})

        if not form.is_valid():
            raise ValidationError(form.errors)

        return VerifyToken(**form.cleaned_data)


class LongRunningToken(ClientIDMutation):
    permission_classes = (IsAuthenticated,)

    long_running_token = graphene.String()
    user = graphene.Field(user_node)

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        token = get_token(context)

        if not token:
            msg = _("Authorization header not found.")
            raise AuthenticationFailed(msg)

        form = LongRunningJWTTokenForm({"token": token})

        if not form.is_valid():
            raise ValidationError(form.errors)

        data = {
            'long_running_token': form.cleaned_data.get('token'),
            'user': form.cleaned_data.get('user')
        }

        return LongRunningToken(**data)


class ObtainNewToken(ClientIDMutation):

    class Input:
        long_running_token = graphene.String(required=True)

    token = graphene.String()
    user = graphene.Field(user_node)

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        input_data = {
            'long_running_token': input.get('long_running_token')
        }

        form = ObtainNewJWTTokenForm(input_data)

        if not form.is_valid():
            raise ValidationError(form.errors)

        data = {
            'token': form.cleaned_data.get('token'),
            'user': form.cleaned_data.get('user')
        }

        return ObtainNewToken(**data)


class Logout(ClientIDMutation):
    status = graphene.String()

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        token = get_token(context)

        if not token:
            return Logout(status='ok')

        form = BlacklistJWTTokenForm({'token': token})

        if not form.is_valid():
            return Logout(status='Ok')

        payload = form.cleaned_data.get('payload')
        user = form.cleaned_data.get('user')

        if jwt_using_blacklist:
            blacklist = jwt_blacklist_get_handler(payload)

            if blacklist is None:
                jwt_blacklist_set_handler(payload)

        if jwt_using_long_running_token and jwt_delete_long_running_token_when_logout:
            long_running_token = jwt_long_running_token_get_handler(user)

            if long_running_token is not None:
                long_running_token.delete()

        return Logout(status='Ok')


class DeleteLongRunningToken(ClientIDMutation):
    status = graphene.String()

    @classmethod
    def mutate_and_get_payload(cls, input, context, info):
        token = get_token(context)

        if not token:
            return DeleteLongRunningToken(status='ok')

        form = BlacklistJWTTokenForm({'token': token})

        if not form.is_valid():
            return DeleteLongRunningToken(status='Ok')

        user = form.cleaned_data.get('user')
        long_running_token = jwt_long_running_token_get_handler(user)

        if long_running_token is not None:
            long_running_token.delete()

        return DeleteLongRunningToken(status='ok')


class Mutation(graphene.AbstractType):
    login = Login.Field()
    refresh_token = RefreshToken.Field()
    verify_token = VerifyToken.Field()
    long_running_token = LongRunningToken.Field()
    delete_long_running_token = DeleteLongRunningToken.Field()
    obtain_new_token = ObtainNewToken.Field()
    logout = Logout.Field()
