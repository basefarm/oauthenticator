"""
Custom Authenticator to use Azure AD with JupyterHub

"""

import json
import jwt
import os
import re
import string
import urllib
import sys
import adal

from tornado.auth import OAuth2Mixin
from tornado.log import app_log
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import List, Set, Unicode

from .common import next_page_from_links
from .oauth2 import OAuthLoginHandler, OAuthenticator

class AzureAdMixin(OAuth2Mixin):
    # tenant_id = os.environ.get('AAD_TENANT_ID', '')
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('_OAUTH_ACCESS_TOKEN_URL')
    _OAUTH_AUTHORIZE_URL = os.environ.get('_OAUTH_AUTHORIZE_URL')


class AzureAdLoginHandler(OAuthLoginHandler, AzureAdMixin):
    pass


class AzureAdOAuthenticator(OAuthenticator):
    
    login_service = "Azure AD"
    login_handler = AzureAdLoginHandler
    tenant_id = Unicode(config=True)

    @gen.coroutine
    def authenticate(self, handler, data=None):

        _OAUTH_AUTHORITY_URL = os.environ.get('_OAUTH_AUTHORITY_URL')
        _OAUTH_GRAPH_RESOURCE = os.environ.get('_OAUTH_GRAPH_RESOURCE')

        code = handler.get_argument("code")
        auth_context = adal.AuthenticationContext(_OAUTH_AUTHORITY_URL)        
        resp_json = auth_context.acquire_token_with_authorization_code(
            code, 
            self.get_callback_url(handler), 
            _OAUTH_GRAPH_RESOURCE,
            self.client_id, 
            self.client_secret
        )
        access_token = resp_json['accessToken']        
        decoded = jwt.decode(access_token, verify=False)

        # return userdict
        return {
            'name': decoded['name'].replace(' ', ''),
            'auth_state': {
                'access_token': resp_json['accessToken'],
                'refresh_token': resp_json['refreshToken'],
                'oauth_user': resp_json,
                'scope': self.scope
            }
        }


class LocalAzureAdOAuthenticator(LocalAuthenticator, AzureAdOAuthenticator):
    """A version that mixes in local system user creation"""
    pass