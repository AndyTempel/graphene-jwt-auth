from django.db import models
from django.utils.timezone import now

from graphene_jwt_auth.settings import api_settings


class JWTBlacklistToken(models.Model):
    jti = models.CharField(max_length=40, primary_key=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()

    class Meta:
        abstract = not api_settings.JWT_USING_BLACKLIST
        verbose_name = 'JWT Blacklist Token'
        verbose_name_plural = 'JWT Blacklist Tokens'

    def __str__(self):
        return self.jti

    def is_active(self):
        return self.expires > now()

    is_active.boolean = True
    is_active.short_description = 'active'
