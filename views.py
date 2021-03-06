from __future__ import absolute_import

import cgi
import logging
import urllib
import urlparse

from django.conf import settings
from django.http import (HttpResponse, HttpResponseRedirect, 
                         HttpResponseNotAllowed, HttpResponseBadRequest)
from django.utils.translation import ugettext as _
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import get_callable

from .decorators import oauth_required
from .models import Token
from .oauth import OAuthError
from .utils import (initialize_server_request, send_oauth_error,
                    add_query_params_to_url)
from .stores import check_valid_callback

OAUTH_AUTHORIZE_VIEW = 'OAUTH_AUTHORIZE_VIEW'
OAUTH_CALLBACK_VIEW = 'OAUTH_CALLBACK_VIEW'
OAUTH_AUTHORIZE_CALLBACK = 'OAUTH_AUTHORIZE_CALLBACK'

INVALID_PARAMS_RESPONSE = send_oauth_error(OAuthError(
                                            _('Invalid request parameters.')))

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

def request_token(request):
    """
    The Consumer obtains an unauthorized Request Token by asking the Service 
    Provider to issue a Token. The Request Token's sole purpose is to receive 
    User approval and can only be used to obtain an Access Token.
    """
    oauth_server, oauth_request = initialize_server_request(request)
    if oauth_server is None:
        return INVALID_PARAMS_RESPONSE
    try:
        # create a request token
        token = oauth_server.fetch_request_token(oauth_request)
        # return the token
        d = token.to_dict()
        if token.is_1_0a_request:
            d['oauth_callback_confirmed'] = 'true'
        response = HttpResponse(urllib.urlencode(d), mimetype="text/plain")
    except OAuthError, err:
        response = send_oauth_error(err)
    return response
    
@login_required
def user_authorization(request):
    """
    The Consumer cannot use the Request Token until it has been authorized by 
    the User.
    """
    oauth_server, oauth_request = initialize_server_request(request)
    if oauth_request is None:
        return INVALID_PARAMS_RESPONSE
    try:
        # get the request toke/verify
        token = oauth_server.fetch_request_token(oauth_request)
    except OAuthError, err:
        return send_oauth_error(err)

    try:
        callback = oauth_server.get_callback(oauth_request)
        if token.is_1_0a_request:
            return HttpResponseBadRequest("Cannot specify oauth_callback at authorization step for 1.0a protocol")
        if not check_valid_callback(callback):
            return HttpResponseBadRequest("Invalid callback URL")
    except OAuthError:
        callback = None
    if token.is_1_0a_request:
        callback = token.callback
        if callback == "oob":
            callback = None

    # entry point for the user
    if request.method == 'GET':
        # try to get custom authorize view
        authorize_view_str = getattr(settings, OAUTH_AUTHORIZE_VIEW, 
                                    'django_oauth.views.fake_authorize_view')
        try:
            authorize_view = get_callable(authorize_view_str)
        except AttributeError:
            raise Exception, "%s view doesn't exist." % authorize_view_str
        params = oauth_request.get_normalized_parameters()
        # set the oauth flag
        request.session['oauth'] = token.key
        return authorize_view(request, token, callback, params)
    
    # user grant access to the service
    elif request.method == 'POST':
        # verify the oauth flag set in previous GET
        if request.session.get('oauth', '') == token.key:
            request.session['oauth'] = ''
            try:
                if request.POST.get('authorize_access') == 'on':
                    # authorize the token
                    token = oauth_server.authorize_token(token, request.user)

                    # let the rest of the django world react if they want
                    if hasattr(settings, OAUTH_AUTHORIZE_CALLBACK):
                        get_callable(settings.OAUTH_AUTHORIZE_CALLBACK)(request, token)

                    # return the token key
                    args = {'oauth_token': token.key}
                    if token.verifier:
                        args['oauth_verifier'] = token.verifier
                else:
                    args = {'error': _('Access not granted by user.')}
            except OAuthError, err:
                response = send_oauth_error(err)
            if callback:
                callback = add_query_params_to_url(callback, args)
                response = HttpResponseRedirect(callback)
            else:
                # try to get custom callback view
                callback_view_str = getattr(settings, OAUTH_CALLBACK_VIEW, 
                                    'django_oauth.views.fake_callback_view')
                try:
                    callback_view = get_callable(callback_view_str)
                except AttributeError:
                    raise Exception, "%s view doesn't exist." % callback_view_str
                response = callback_view(request, **args)
        else:
            response = send_oauth_error(OAuthError(_('Action not allowed.')))
        return response
    
def access_token(request):
    """
    The Consumer exchanges the Request Token for an Access Token capable of 
    accessing the Protected Resources.
    """
    oauth_server, oauth_request = initialize_server_request(request)
    if oauth_request is None:
        return INVALID_PARAMS_RESPONSE
    try:
        # get the request token
        token = oauth_server.fetch_request_token(oauth_request)
    except OAuthError, err:
        return send_oauth_error(err)
    try:
        # get the access token
        token = oauth_server.fetch_access_token(oauth_request)
        # return the token
        d = token.to_dict()
        response = HttpResponse(urllib.urlencode(d), mimetype="text/plain")
    except OAuthError, err:
        response = send_oauth_error(err)
    return response

@login_required
def revoke_token(request):
    if request.method == 'POST':
        if 'todelete' in request.POST:
            key = request.POST['todelete']
            request.user.token_set.filter(key=key).delete()
            log.info("OAuth token %s for user %s has been revoked" % (key, request.user))
            return HttpResponse('The token has been revoked.')
    else:
        return HttpResponseNotAllowed(['POST'])

@oauth_required
def protected_resource_example(request):
    """
    Test view for accessing a Protected Resource.
    """
    return HttpResponse('Protected Resource access!')

@login_required
def fake_authorize_view(request, token, callback, params):
    """
    Fake view for tests. It must return an ``HttpResponse``.
    
    You need to define your own in ``settings.OAUTH_AUTHORIZE_VIEW``.
    """
    return HttpResponse('Fake authorize view for %s.' % token.consumer.name)

def fake_callback_view(request):
    """
    Fake view for tests. It must return an ``HttpResponse``.

    You can define your own in ``settings.OAUTH_CALLBACK_VIEW``.
    """
    return HttpResponse('Fake callback view.')
