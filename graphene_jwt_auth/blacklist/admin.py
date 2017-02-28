from django.contrib import admin

from graphene_jwt_auth.blacklist.models import JWTBlacklistToken
from graphene_jwt_auth.settings import api_settings


class JWTBlacklistTokenAdmin(admin.ModelAdmin):
    list_display = ('jti', 'expires', 'created', 'is_active')
    fields = ('jti', 'expires', 'created', 'is_active')
    readonly_fields = ('jti', 'expires', 'created', 'is_active')


if api_settings.JWT_USING_BLACKLIST:
    admin.site.register(JWTBlacklistToken, JWTBlacklistTokenAdmin)
