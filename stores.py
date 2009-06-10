from __future__ import absolute_import

from django.core.cache import cache

from .models import Token, Consumer, Resource
from .oauth import OAuthDataStore,OAuthError
from .oauth import escape as OAuthEscape

class DataStore(OAuthDataStore):
    """Layer between Python OAuth and Django database."""
    def __init__(self, oauth_request):
        self.signature = oauth_request.parameters.get('oauth_signature', None)
        self.timestamp = oauth_request.parameters.get('oauth_timestamp', None)
        self.scope = oauth_request.parameters.get('scope', 'all')

    def lookup_consumer(self, key):
        try:
            self.consumer = Consumer.objects.get(key=key)
            return self.consumer
        except Consumer.DoesNotExist:
            return None

    def lookup_token(self, token_type, token):
        if token_type == 'request':
            token_type = Token.REQUEST
        elif token_type == 'access':
            token_type = Token.ACCESS
        try:
            self.request_token = Token.objects.get(key=token, 
                                                   token_type=token_type)
            return self.request_token
        except Token.DoesNotExist:
            return None

    def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
        # The OAuth token may be None for an initial request
        token_key = oauth_token and oauth_token.key or ''
        nonce_key = "%s-%s-%s" % (oauth_consumer.key, token_key, nonce)
        v = cache.get(nonce_key)
        if v:
            return nonce_key
        else:
            cache.set(nonce_key, True, 300)

    def fetch_request_token(self, oauth_consumer):
        if oauth_consumer.key == self.consumer.key:
            try:
                resource = Resource.objects.get(name=self.scope)
            except:
                raise OAuthError('Resource %s does not exist.' % OAuthEscape(self.scope))
            self.request_token = Token.objects.create_token(consumer=self.consumer,
                                                            token_type=Token.REQUEST,
                                                            timestamp=self.timestamp,
                                                            resource=resource)
            return self.request_token
        raise OAuthError('Consumer key does not match.')

    def fetch_access_token(self, oauth_consumer, oauth_token):
        if oauth_consumer.key == self.consumer.key \
        and oauth_token.key == self.request_token.key \
        and self.request_token.is_approved:
            self.access_token = Token.objects.create_token(consumer=self.consumer,
                                                           token_type=Token.ACCESS,
                                                           timestamp=self.timestamp,
                                                           user=self.request_token.user,
                                                           resource=self.request_token.resource)
            return self.access_token
        raise OAuthError('Consumer key or token key does not match. Make sure your request token has been approved too.')

    def authorize_request_token(self, oauth_token, user):
        if oauth_token.key == self.request_token.key:
            # authorize the request token in the store
            self.request_token.is_approved = True
            self.request_token.user = user
            self.request_token.save()
            return self.request_token
        raise OAuthError('Token key does not match.')
