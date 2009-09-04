from __future__ import absolute_import

import urllib

from django.db import models
from django.contrib.auth.models import User

from .managers import TokenManager, ConsumerManager, ResourceManager
from .consts import KEY_SIZE, SECRET_SIZE


class Resource(models.Model):
    name = models.CharField(max_length=255)
    url = models.TextField(max_length=2047)
    is_readonly = models.BooleanField(default=True)
    
    objects = ResourceManager()

    def __unicode__(self):
        return u"Resource %s with url %s" % (self.name, self.url)


class Consumer(models.Model):
    name = models.CharField(max_length=255)
    key = models.CharField(max_length=KEY_SIZE, null=True, blank=True)
    secret = models.CharField(max_length=SECRET_SIZE, null=True, blank=True)
    
    user = models.ForeignKey(User)
    url = models.URLField(blank=True)
    description = models.TextField(blank=True)
    
    objects = ConsumerManager()
        
    def __unicode__(self):
        return u"Consumer %s with key %s" % (self.name, self.key)

    def generate_random_codes(self):
        key = User.objects.make_random_password(length=KEY_SIZE)
        secret = User.objects.make_random_password(length=SECRET_SIZE)
        while Consumer.objects.filter(key__exact=key, secret__exact=secret).count():
            secret = User.objects.make_random_password(length=SECRET_SIZE)
        self.key = key
        self.secret = secret
        self.save()

    def generate_key_and_empty_secret(self):
        key = User.objects.make_random_password(length=KEY_SIZE)
        secret = ""
        while Token.objects.filter(key__exact=key, secret__exact=secret).count():
            key = User.objects.make_random_password(length=KEY_SIZE)
        self.key = key
        self.secret = secret
        self.save()


class Token(models.Model):
    REQUEST = 1
    ACCESS = 2
    REQUEST_1_0a = 3
    TOKEN_TYPES = ((REQUEST, u'Request'),
                   (ACCESS, u'Access'),
                   (REQUEST_1_0a, u'Request 1.0a'))
    
    key = models.CharField(max_length=KEY_SIZE)
    secret = models.CharField(max_length=SECRET_SIZE)
    token_type = models.IntegerField(choices=TOKEN_TYPES)
    timestamp = models.IntegerField()
    is_approved = models.BooleanField(default=False)

    # Only used at the moment if this is an API token
    name = models.CharField(max_length=50, null=True, blank=True)
    
    user = models.ForeignKey(User, null=True, blank=True)
    consumer = models.ForeignKey(Consumer)
    resource = models.ForeignKey(Resource)
    
    objects = TokenManager()

    def __unicode__(self):
        return u"%s Token %s for %s" % (self.get_token_type_display(), self.key, self.consumer)

    def to_string(self):
        token_dict = {
            'oauth_token': self.key, 
            'oauth_token_secret': self.secret
        }
        if self.token_type == self.REQUEST_1_0a:
            token_dict['oauth_callback_confirmed'] = 'true'
        return urllib.urlencode(token_dict)

    def generate_random_codes(self):
        key = User.objects.make_random_password(length=KEY_SIZE)
        secret = User.objects.make_random_password(length=SECRET_SIZE)
        while Token.objects.filter(key__exact=key, secret__exact=secret).count():
            secret = User.objects.make_random_password(length=SECRET_SIZE)
        self.key = key
        self.secret = secret
        self.save()
