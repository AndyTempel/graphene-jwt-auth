import binascii

from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404 as _get_object_or_404
from graphene.relay.mutation import ClientIDMutation as GClientIDMutation
from graphql_relay.node.node import from_global_id

from graphene_jwt_auth.compat import is_authenticated
from graphene_jwt_auth.exceptions import NotAuthenticated, NotFound, PermissionDenied, Throttled


class ClientIDMutation(GClientIDMutation):
    permission_classes = []
    throttle_classes = []

    # for Django Model Permissions
    model = None

    # for permissions
    method = None  # 'CREATE', 'UPDATE', 'DELETE' only this 3 accepted
    form_class = None

    lookup_field = 'pk'
    lookup_kwarg = None

    @classmethod
    def mutate(cls, root, args, context, info):
        # check permissions first
        cls.check_permission(context)

        # check throttle
        cls.check_throttles(context)

        return super(ClientIDMutation, cls).mutate(root, args, context, info)

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
        return [permission() for permission in cls.permission_classes]

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
        return [throttle() for throttle in cls.throttle_classes]

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

        assert self.method is not None, "Method is required for run `run_cud`."

        self.method = self.method.upper()

        assert self.method in ['CREATE', 'UPDATE', 'DELETE'], (
            "Method {} unknown.".format(repr(self.method))
        )

        global_id = data.get('id')

        assert global_id is not None and self.method in ['UPDATE', 'DELETE'], (
            "`id` must be included in input for method 'UPDATE'and 'DELETE"
        )

        if self.method in ['UPDATE', 'DELETE']:
            self.set_lookup_kwarg(global_id)
            data.pop('id')

        if self.method == 'CREATE':
            return self.create(data)
        elif self.method == 'UPDATE':
            return self.update(data)
        elif self.method == 'DELETE':
            return self.delete()

    def set_lookup_kwarg(self, global_id):
        try:
            _type, _id = from_global_id(global_id)
        except (TypeError, ValueError, UnicodeDecodeError, binascii.Error):
            raise ValidationError("Invalid id.")

        self.lookup_kwarg = _id

    def get_object(self):
        filter_kwargs = {self.lookup_field: self.lookup_kwarg}

        obj = self.get_object_or_404(self.model, **filter_kwargs)

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
        form = self.form_class(data=data)
        if not form.is_valid():
            raise ValidationError(form.errors)

        instance = self.perform_create(form)

        return instance

    def perform_create(self, form):
        return form.save()

    def update(self, data):
        instance = self.get_object()

        form = self.form_class(instance=instance, data=data)

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
