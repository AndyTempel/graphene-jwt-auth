import binascii
import re
from functools import partial

import six
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404 as _get_object_or_404
from graphene.types import AbstractType, Argument, Field, InputObjectType, String
from graphene.types.objecttype import ObjectType, ObjectTypeMeta
from graphene.types.options import Options
from graphene.utils.is_base_type import is_base_type
from graphene.utils.props import props
from graphene_django.utils import is_valid_django_model
from graphql_relay.node.node import from_global_id
from promise import Promise

from graphene_jwt_auth.compat import is_authenticated
from graphene_jwt_auth.exceptions import NotAuthenticated, NotFound, PermissionDenied, Throttled


class ClientIDMutationMeta(ObjectTypeMeta):

    def __new__(cls, name, bases, attrs):
        # Also ensure initialization is only performed for subclasses of
        # Mutation
        if not is_base_type(bases, ClientIDMutationMeta):
            return type.__new__(cls, name, bases, attrs)

        defaults = dict(
            name=name,
            description=attrs.pop('__doc__', None),
            interfaces=(),
            local_fields=None,
            permission_classes=(),
            throttle_classes=(),

            # for Django Model Permissions
            model=None,

            # for permissions
            method=None,  # 'CREATE', 'UPDATE', 'DELETE' only this 3 accepted
            form_class=None,

            lookup_field='pk',
            lookup_kwarg=None
        )

        options = Options(
            attrs.pop('Config', None),
            **defaults
        )

        if options.model is not None:
            assert is_valid_django_model(options.model), (
                'You need to pass a valid Django Model in {}.Meta, received "{}".'
            ).format(name, options.model)

        input_class = attrs.pop('Input', None)
        base_name = re.sub('Payload$', '', name)
        if 'client_mutation_id' not in attrs:
            attrs['client_mutation_id'] = String(name='clientMutationId')
        cls = ObjectTypeMeta.__new__(cls, '{}Payload'.format(base_name), bases, dict(attrs, _meta=options))
        mutate_and_get_payload = getattr(cls, 'mutate_and_get_payload', None)
        if cls.mutate and cls.mutate.__func__ == ClientIDMutation.mutate.__func__:
            assert mutate_and_get_payload, (
                "{}.mutate_and_get_payload method is required"
                " in a ClientIDMutation."
            ).format(name)
        input_attrs = {}
        bases = ()
        if not input_class:
            input_attrs = {}
        elif not issubclass(input_class, AbstractType):
            input_attrs = props(input_class)
        else:
            bases += (input_class, )
        input_attrs['client_mutation_id'] = String(name='clientMutationId')
        cls.Input = type('{}Input'.format(base_name), bases + (InputObjectType,), input_attrs)
        cls.Field = partial(Field, cls, resolver=cls.mutate, input=Argument(cls.Input, required=True))

        return cls


class ClientIDMutation(six.with_metaclass(ClientIDMutationMeta, ObjectType)):

    @classmethod
    def mutate(cls, root, args, context, info):
        cls.check_permission(context)
        # cls.check_throttles(context)

        input = args.get('input')

        def on_resolve(payload):
            try:
                payload.client_mutation_id = input.get('clientMutationId')
            except:
                raise Exception((
                    'Cannot set client_mutation_id in the payload object {}'
                ).format(repr(payload)))
            return payload

        return Promise.resolve(
            cls.mutate_and_get_payload(input, context, info)
        ).then(on_resolve)


    # Permission
    # ==========
    @classmethod
    def check_permission(cls, context):
        """
        Check if the request should be premitted.
        Raises an appropriate exception if the request is not permitted.
        """
        for permission in cls.get_permissions():
            if not permission.has_permission(context, cls):
                cls.permission_denied(context)

    @classmethod
    def get_permissions(cls):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        return [permission() for permission in cls._meta.permission_classes]

    @classmethod
    def permission_denied(cls, context):
        if not (context.user and is_authenticated(context.user)):
            raise NotAuthenticated()
        raise PermissionDenied()

    # Throttle
    # ========
    @classmethod
    def check_throttles(cls, context):
        """
        Check if request should be throttled.
        Raises an appropriate exception if the request is throttled.
        """
        for throttle in cls.get_throttles():
            if not throttle.allow_request(context, cls):
                cls.throttled(context, throttle.wait())

    @classmethod
    def get_throttles(cls):
        return [throttle() for throttle in cls._meta.throttle_classes]

    @classmethod
    def throttled(cls, request, wait):
        """
        If request is throttled, determine what kind of exception to raise.
        """
        raise Throttled(wait)

    # Create update delete method
    # ============================
    def run_cud(self, data):
        """
        Just run run_cud(input) from your get_mutate_and_payload()
        this will return instance
        """

        assert self._meta.method is not None, "Method is required for run `run_cud`."

        method = self._meta.method.upper()

        assert method in ['CREATE', 'UPDATE', 'DELETE'], (
            "Method {} unknown.".format(repr(method))
        )

        global_id = data.get('id')

        assert global_id is not None and method in ['UPDATE', 'DELETE'], (
            "`id` must be included in input for method 'UPDATE'and 'DELETE"
        )

        if method in ['UPDATE', 'DELETE']:
            self.set_lookup_kwarg(global_id)
            data.pop('id')

        if method == 'CREATE':
            return self.create(data)
        elif method == 'UPDATE':
            return self.update(data)
        elif method == 'DELETE':
            return self.delete()

    def set_lookup_kwarg(self, global_id):
        try:
            _type, _id = from_global_id(global_id)
        except (TypeError, ValueError, UnicodeDecodeError, binascii.Error):
            raise ValidationError("Invalid id.")

        self._meta.lookup_kwarg = _id

    def get_object(self):
        filter_kwargs = {self._meta.lookup_field: self._meta.lookup_kwarg}

        obj = self.get_object_or_404(self._meta.model, **filter_kwargs)

        return obj

    @staticmethod
    def get_object_or_404(queryset, *filter_args, **filter_kwargs):
        """
        Same as Django's standard shortcut, but make sure to also raise 404
        if the filter_kwargs don't match the required types.
        """
        try:
            return _get_object_or_404(queryset, *filter_args, **filter_kwargs)
        except (TypeError, ValueError):
            raise NotFound()

    def create(self, data):
        form = self._meta.form_class(data=data)
        if not form.is_valid():
            raise ValidationError(form.errors)

        instance = self.perform_create(form)

        return instance

    def perform_create(self, form):
        return form.save()

    def update(self, data):
        instance = self.get_object()

        form = self._meta.form_class(instance=instance, data=data)

        if not form.is_valid():
            raise ValidationError(form.errors)

        instance = self.perform_update(form)

        return instance

    def perform_update(self, form):
        return form.save()

    def delete(self):
        instance = self.get_object()
        self.perform_delete(instance)

        return instance

    def perform_delete(self, instance):
        instance.delete()
