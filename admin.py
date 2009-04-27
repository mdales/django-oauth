from __future__ import absolute_import

from django.contrib import admin

from .models import Resource, Consumer, Token

admin.site.register(Resource)
admin.site.register(Consumer)
admin.site.register(Token)