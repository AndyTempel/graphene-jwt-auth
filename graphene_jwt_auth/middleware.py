from django.contrib.auth.models import AnonymousUser
from django.utils.functional import SimpleLazyObject

from graphene_jwt_auth.authentication import JSONWebTokenAuthentication
from graphene_jwt_auth.compat import is_authenticated


def get_user_jwt(request):
    # check first if request.user is available
    # if django still use session
    user = JSONWebTokenAuthentication().authenticate(request)
    return user[0] or AnonymousUser()


class DjangoJWTAuthenticationMiddleware(object):
    """
    Token base authentication using the JSON Web Token standard.
    This middleware used in django middleware.

    Clients should authenticate by passing the token key in "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
        TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not (request.user and is_authenticated(request.user)):
            request.user = SimpleLazyObject(lambda: get_user_jwt(request))

        return self.get_response(request)


class GrapheneJWTAuthenticationMiddleware(object):
    """
    Token base authentication using the JSON Web Token standard.
    This middleware used in graphene middleware.

     Clients should authenticate by passing the token key in "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.
        TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
    """
    def resolve(self, next, root, args, context, info):
        if not (context.user and is_authenticated(context.user)):
            context.user = SimpleLazyObject(lambda: get_user_jwt(context))

        return next(root, args, context, info)
