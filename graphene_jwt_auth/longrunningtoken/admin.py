from django.contrib import admin

from graphene_jwt_auth.longrunningtoken.models import JWTLongRunningToken
from graphene_jwt_auth.settings import api_settings


class JWTLongRunningTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'key', 'created', 'expires', 'is_active')
    fields = ('user', 'key', 'app', 'created', 'expires', 'is_active')
    readonly_fields = ('user', 'key', 'app', 'created', 'expires', 'is_active')


if api_settings.JWT_USING_LONG_RUNNING_TOKEN:
    admin.site.register(JWTLongRunningToken, JWTLongRunningTokenAdmin)
