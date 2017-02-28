from graphene import AbstractType, relay
from graphene_django.filter import DjangoFilterConnectionField
from graphene_django.types import DjangoObjectType

from graphene_jwt_auth.compat import User


class UserNode(DjangoObjectType):
    class Meta:
        model = User
        # we not use only_fields because too much
        exclude_fields = ('password',)
        interfaces = (relay.Node,)


class Query(AbstractType):
    user = relay.Node.Field(UserNode)
    users = DjangoFilterConnectionField(UserNode)
