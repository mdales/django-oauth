from __future__ import absolute_import

from django.conf import settings
from django.http import HttpResponse

from . import oauth
from .oauth import OAuthRequest, OAuthServer, build_authenticate_header
from .stores import DataStore

OAUTH_REALM_KEY_NAME = 'OAUTH_REALM_KEY_NAME'

def initialize_server_request(request, signature_methods=None):
    """Shortcut for initialization."""
    # Django converts Authorization header in HTTP_AUTHORIZATION
    # Warning: it doesn't happen in tests but it's useful, do not remove!
    if signature_methods is None:
        signature_methods = ["PLAINTEXT", "HMAC_SHA1"]
    auth_header = {}
    if 'Authorization' in request.META:
        auth_header = {'Authorization': request.META['Authorization']}
    elif 'HTTP_AUTHORIZATION' in request.META:
        auth_header =  {'Authorization': request.META['HTTP_AUTHORIZATION']}

    params = request.GET.copy()
    # According to 9.1.1, we must not include params from multipart/form-data POST
    if (request.method == "POST" and
        request.META['CONTENT_TYPE'] == "application/x-www-form-urlencoded"):
        # a QueryDict update will preserve multiple values.
        params.update(request.POST)
    oauth_request = OAuthRequest.from_request(request.method,
                                              request.build_absolute_uri(),
                                              headers=auth_header,
                                              parameters=params,
                                              query_string=request.environ.get('QUERY_STRING', ''))
    if oauth_request:
        oauth_server = OAuthServer(DataStore(oauth_request))
        for signature_method in signature_methods:
            try:
                signature_function = getattr(oauth, "OAuthSignatureMethod_"+signature_method)
            except AttributeError:
                raise ValueError("No such OAuth signature method defined")
            oauth_server.add_signature_method(signature_function())
    else:
        oauth_server = None
    return oauth_server, oauth_request

def send_oauth_error(err=None):
    """Shortcut for sending an error."""
    # send a 401 error
    response = HttpResponse(err.message.encode('utf-8'), mimetype="text/plain")
    response.status_code = 401
    # return the authenticate header
    realm = getattr(settings, OAUTH_REALM_KEY_NAME, '')
    header = build_authenticate_header(realm=realm)
    for k, v in header.iteritems():
        response[k] = v
    return response
