"""
Code taken from django-rest-framework
https://github.com/tomchristie/django-rest-framework/blob/master/rest_framework/permissions.py
"""
from graphene_jwt_auth.compat import is_authenticated
from graphene_jwt_auth.exceptions import MethodNotAllowed


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


class IsAnonymous(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_anonymous


class DjangoModelPermissions(BasePermission):
    """
    The request is authenticated using `django.contrib.auth` permissions.
    See: https://docs.djangoproject.com/en/dev/topics/auth/#permissions
    It ensures that the user is authenticated, and has the appropriate
    `add`/`change`/`delete` permissions on the model.
    This permission can only be applied against view classes that
    provide a `.queryset` attribute.
    """

    # Map methods into required permission codes.
    # Override this if you need to also provide 'view' permissions,
    # or if you want to provide custom permission codes.
    perms_map = {
        'CREATE': ['%(app_label)s.add_%(model_name)s'],
        'READ': ['%(app_label)s.read_%(model_name)s'],
        'UPDATE': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    authenticated_users_only = True

    def get_required_permissions(self, method, model_cls):
        """
        Given a model and an HTTP method, return the list of permission
        codes that the user is required to have.
        """
        kwargs = {
            'app_label': model_cls._meta.app_label,
            'model_name': model_cls._meta.model_name
        }

        if method not in self.perms_map:
            raise MethodNotAllowed(method)

        return [perm % kwargs for perm in self.perms_map[method]]

    def has_permission(self, request, view):
        model = view.model
        method = view.method

        assert model is not None, (
            'Cannot apply DjangoModelPermissions on a view that '
            'does not set `model`.'
        )

        assert method is not None, (
            'Cannot apply DjangoModelPermissions on a view that '
            'does not set `method`.'
        )

        perms = self.get_required_permissions(method, model)

        return (
            request.user and
            (is_authenticated(request.user) or not self.authenticated_users_only) and
            request.user.has_perms(perms)
        )


class DjangoModelPermissionsOrAnonReadOnly(DjangoModelPermissions):
    """
    Similar to DjangoModelPermissions, except that anonymous users are
    allowed read-only access.
    """
    authenticated_users_only = False
