import six
from graphene.relay.mutation import ClientIDMutationMeta
from graphene.types.objecttype import ObjectType
from promise import Promise

from graphene_jwt_auth.compat import is_authenticated
from graphene_jwt_auth.exceptions import NotAuthenticated, PermissionDenied


class ClientIDMutation(six.with_metaclass(ClientIDMutationMeta, ObjectType)):
    permission_classes = []

    @classmethod
    def mutate(cls, root, args, context, info):

        # Check permissions first
        # TODO : still need improve this mutation with auth
        # im not happy with this implementation, i don't know why i can't use super on this method
        cls.check_permission(context)

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

    @classmethod
    def get_permissions(cls):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        return [permission() for permission in cls.permission_classes]

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
    def permission_denied(cls, context):
        if not (context.user and is_authenticated(context.user)):
            raise NotAuthenticated()
        raise PermissionDenied()
