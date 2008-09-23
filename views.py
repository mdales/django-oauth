from __future__ import absolute_import

from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext as _
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import get_callable

from .decorators import oauth_required
from .oauth import OAuthError
from .utils import initialize_server_request, send_oauth_error

OAUTH_AUTHORIZE_VIEW = 'OAUTH_AUTHORIZE_VIEW'
INVALID_PARAMS_RESPONSE = send_oauth_error(OAuthError(
                                            _('Invalid request parameters.')))

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
        response = HttpResponse(token.to_string())
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
        # get the request token
        token = oauth_server.fetch_request_token(oauth_request)
    except OAuthError, err:
        return send_oauth_error(err)
        
    try:
        # get the request callback, though there might not be one
        callback = oauth_server.get_callback(oauth_request)
    except OAuthError:
        callback = None

    # entry point for the user
    if request.method == 'GET':
        # try to get custom view
        authorize_view_str = getattr(settings, OAUTH_AUTHORIZE_VIEW, 
                                    'oauth.views.fake_custom_view')
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
                if request.POST['authorize_access'] == 'on':
                    # authorize the token
                    token = oauth_server.authorize_token(token, request.user)
                    # return the token key
                    args = token.to_string(only_key=True)
                else:
                    args = 'error=%s' % _('Access not granted by user.')
                if callback:                    
                    response = HttpResponseRedirect('%s?%s' % (callback, args))
                else:
                    # Not sure what to do here - i'll deal with it later
                    response = HttpResponse("Authorized")
            except OAuthError, err:
                response = send_oauth_error(err)
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
        token = oauth_server.fetch_access_token(oauth_request)
        # return the token
        response = HttpResponse(token.to_string())
    except OAuthError, err:
        response = send_oauth_error(err)
    return response

@oauth_required
def protected_resource_example(request):
    """
    Test view for accessing a Protected Resource.
    """
    return HttpResponse('Protected Resource access!')

@login_required
def fake_custom_view(request, token, callback, params):
    """
    Fake view for tests. It must return an ``HttpResponse``.
    
    You need to define your own in ``settings.OAUTH_AUTHORIZE_VIEW``.
    """
    return HttpResponse('Fake custom view for %s.' % token.consumer.name)
