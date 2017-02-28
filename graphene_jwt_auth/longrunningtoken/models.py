from django.conf import settings
from django.db import models
from django.utils.timezone import now

from graphene_jwt_auth.settings import api_settings
from graphene_jwt_auth.utils import generate_key


class JWTLongRunningToken(models.Model):
    key = models.CharField('Key', max_length=40, primary_key=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, related_name='long_running_tokens',
        on_delete=models.CASCADE, verbose_name='User'
    )
    app = models.CharField(max_length=255)
    created = models.DateTimeField("Created", auto_now_add=True)
    # expires taken from JWT_REFRESH_EXPIRATION_DELTA
    expires = models.DateTimeField()

    class Meta:
        abstract = not api_settings.JWT_USING_LONG_RUNNING_TOKEN
        verbose_name = "Long Running Token"
        verbose_name_plural = "Long Running Tokens"

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = generate_key()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.key

    def is_active(self):
        return self.expires > now()

    is_active.boolean = True
    is_active.short_description = 'active'
