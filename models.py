from __future__ import absolute_import

from django.db import models
from django.contrib.auth.models import User

from .managers import TokenManager, ConsumerManager, ResourceManager

KEY_SIZE = 16
SECRET_SIZE = 16
VERIFIER_SIZE = 8
MAX_URL_LENGTH = 2083


class Resource(models.Model):
    name = models.CharField(max_length=255)
    url = models.TextField(max_length=MAX_URL_LENGTH)
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
    verifier = models.CharField(max_length=VERIFIER_SIZE, null=True, blank=True)
    callback = models.CharField(max_length=MAX_URL_LENGTH, null=True, blank=True)

    # Only used at the moment if this is an API token
    name = models.CharField(max_length=50, null=True, blank=True)
    
    user = models.ForeignKey(User, null=True, blank=True)
    consumer = models.ForeignKey(Consumer)
    resource = models.ForeignKey(Resource)
    
    objects = TokenManager()

    def __unicode__(self):
        return u"%s Token %s for %s" % (self.get_token_type_display(), self.key, self.consumer)

    @property
    def is_1_0a_request(self):
        return self.token_type == Token.REQUEST_1_0a

    def to_dict(self):
        return {
            'oauth_token': self.key, 
            'oauth_token_secret': self.secret
        }

    def generate_random_codes(self):
        key = User.objects.make_random_password(length=KEY_SIZE)
        secret = User.objects.make_random_password(length=SECRET_SIZE)
        while Token.objects.filter(key__exact=key, secret__exact=secret).count():
            secret = User.objects.make_random_password(length=SECRET_SIZE)
        self.key = key
        self.secret = secret
        if self.is_1_0a_request:
            self.verifier = \
                User.objects.make_random_password(length=VERIFIER_SIZE)
        self.save()
