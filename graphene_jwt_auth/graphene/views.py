# Create your views here.
import six
from graphene_django.views import GraphQLView
from graphql.error import GraphQLError

from .utils import format_error as format_graphql_error


class CustomGraphQLView(GraphQLView):

    @staticmethod
    def format_error(error):
        if isinstance(error, GraphQLError):
            return format_graphql_error(error)

        return {'message': six.text_type(error)}
