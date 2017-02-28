from graphene_jwt_auth.compat import is_authenticated


class BasePermission(object):
    """
    A base class from which all permission classes should inherit.
    """

    def has_permission(self, request, view):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True

    def has_object_permission(self, request, view, obj):
        """
        Return `True` if permission is granted, `False` otherwise.
        """
        return True


class IsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        return request.user and is_authenticated(request.user)


class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and is_authenticated(request.user) and request.user.is_staff


class IsSuperUser(BasePermission):
    def has_permission(self, request, view):
        return request.user and is_authenticated(request.user) and request.user.is_superuser
