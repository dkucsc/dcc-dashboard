"""
TODO:
    - Make it so that you don't need to start the command line with
      "OAUTHLIB_INSECURE_TRANSPORT=1"

    - Consider port forwarding ec2 security group port settings, so that the
      redirect from Github works correctly.
"""


import json
import os, sys
import logging
from argparse import ArgumentParser
import subprocess, shlex
import hashlib, pickle

import flask
import six.moves.http_client as httplib
from flask import request, session, redirect, url_for
from flask.json import jsonify
import requests
from requests_oauthlib import OAuth2Session
from flask_debugtoolbar import DebugToolbarExtension
from flask import current_app
from oauth2client.contrib.flask_util import UserOAuth2
from oauth2client import client
from oauth2client.contrib import dictionary_storage
from oauth2client.contrib.flask_util import _CREDENTIALS_KEY, _DEFAULT_SCOPES
from oauth2client.contrib.flask_util import _CSRF_KEY, _FLOW_KEY
from oauth2client.contrib.flask_util import _get_flow_for_token
import oauth2client


API_SERVER = 'github.com/login/oauth'
OAUTH_INSECURE_TRANSPORT_VALUE = '1'
DASHBOARD_SERVER_PORT = 8000
BASE_CLIENT_URL = 'http://0.0.0.0:%s/' % DASHBOARD_SERVER_PORT
DEFAULT_APP_REDIRECT_URI = '%sgithub_callback' % BASE_CLIENT_URL


parser = ArgumentParser(description="UCSC Genomics Institute Dashboard", usage="%(prog)s [options] CLIENT_ID CLIENT_SECRET PORT")
parser.add_argument('--github-client-id', dest='github_client_id', help="Github client ID")
parser.add_argument("--github-client-secret", dest='github_client_secret', help='Github client secret')
parser.add_argument('--google-client-id', dest='google_client_id', help="Google client ID")
parser.add_argument("--google-client-secret", dest='google_client_secret', help='Google client secret')
parser.add_argument("--port", help='The port to listen on', type=int, default=8000)
parser.add_argument("-o", "--oauth-environ", dest="oauth_environ", action='store_true', default=False, help="Whether or not to set the OAUTHLIB_INSECURE_TRANSPORT environment variable to '%s'." % OAUTH_INSECURE_TRANSPORT_VALUE)
parser.add_argument("-a", "--github-api-server", dest="github_api_server", default=API_SERVER, help="Almost always: [github.com]")
parser.add_argument('--github-scopes', dest='github_scopes', action='append', default=[], help='Your requested Github scopes.')
parser.add_argument('--google-scopes', dest='google_scopes', action='append', default=[], help='Your requested Google scopes.')
parser.add_argument("-d", "--debug", dest="debug", action="store_true", default=False, help="Whether or not to provide debugging output.")
parser.add_argument("-r", "--app-redirect-uri", dest="app_redirect_uri", default=DEFAULT_APP_REDIRECT_URI, help="Your client's redirect_uri [%s]" % DEFAULT_APP_REDIRECT_URI)
args = parser.parse_args()


AUTHORIZATION_BASE_URL = 'https://github.com/login/oauth/authorize'
GOOGLE_AUTHORIZATION_BASE_URL = 'https://accounts.google.com/o/oauth2/oauth'
GOOGLE_TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"
TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_DEFAULT_SCOPES = []      # A list of no scopes defaults to public
                                # information, which I think is fine for a
                                # default.
GOOGLE_DEFAULT_SCOPES = []
BASE_API_URL = "https://%s" % args.github_api_server
API_AUTH_URL = '%s/authorize' % BASE_API_URL
github_client_id = args.github_client_id
github_client_secret = args.github_client_secret
google_client_id = args.google_client_id
google_client_secret = args.google_client_secret
github_scopes = args.github_scopes or GITHUB_DEFAULT_SCOPES
google_scopes = args.google_scopes or GOOGLE_DEFAULT_SCOPES
app_redirect_uri = args.app_redirect_uri
DEBUG = args.debug

log = logging
app = flask.Flask(__name__)
app.config['GOOGLE_OAUTH2_CLIENT_ID'] = '872012202875-cjhcvg8t6al188dk122hlfnogqdl8bt2.apps.googleusercontent.com'
app.config['GOOGLE_OAUTH2_CLIENT_SECRET'] = google_client_secret
app.secret_key = os.urandom(24)
if DEBUG:
    app.logger.setLevel(logging.DEBUG)
    app.debug = True
    toolbar = DebugToolbarExtension(app)
#github_oauth2 = UCSCUserOAuth2(app, client_id='7156cfa0c982a6621530', client_secret=github_client_secret, blueprint_name='github')
oauth2 = UserOAuth2(app, client_id='872012202875-cjhcvg8t6al188dk122hlfnogqdl8bt2.apps.googleusercontent.com', client_secret=google_client_secret)


@app.route("/oauth2authorize")
def callback2():
    print("Dumbar")
    return redirect(url_for('home'))


def _make_flow(return_url=None, **kwargs):
    """Creates a Web Server Flow"""
    # Generate a CSRF token to prevent malicious requests.
    csrf_token = hashlib.sha256(os.urandom(1024)).hexdigest()
    session[_CSRF_KEY] = csrf_token
    state = json.dumps({
        'csrf_token': csrf_token,
        'return_url': return_url
    })
    kw = oauth2.flow_kwargs.copy()
    kw.update(kwargs)
    extra_scopes = kw.pop('scopes', [])
    scopes = set(oauth2.scopes).union(set(extra_scopes))
    flow = client.OAuth2WebServerFlow(client_id=oauth2.client_id,
        client_secret=oauth2.client_secret, scope=scopes,
        state=state,
        redirect_uri=url_for('google_callback', _external=True), **kw)
    flow_key = _FLOW_KEY.format(csrf_token)
    session[flow_key] = pickle.dumps(flow)
    return flow
@app.route("/google_authorize_view")
def google_authorize_view():
    """Flask view that starts the authorization flow.

    Starts flow by redirecting the user to the OAuth2 provider.
    """
    args = request.args.to_dict()

    # Scopes will be passed as mutliple args, and to_dict() will only
    # return one. So, we use getlist() to get all of the scopes.
    args['scopes'] = request.args.getlist('scopes')

    return_url = args.pop('return_url', None)
    if return_url is None:
        return_url = request.referrer or '/'

    flow = _make_flow(return_url=return_url, **args)
    auth_url = flow.step1_get_authorize_url()

    return redirect(auth_url)


@app.route("/google_callback")
def google_callback():
    """Flask view that handles the user's return from OAuth2 provider.

    On return, exchanges the authorization code for credentials and stores
    the credentials.
    """
    if 'error' in request.args:
        reason = request.args.get(
            'error_description', request.args.get('error', ''))
        return ('Authorization failed: {0}'.format(reason),
                httplib.BAD_REQUEST)

    try:
        encoded_state = request.args['state']
        server_csrf = session[_CSRF_KEY]
        code = request.args['code']
    except KeyError:
        return 'Invalid request', httplib.BAD_REQUEST

    try:
        state = json.loads(encoded_state)
        client_csrf = state['csrf_token']
        return_url = state['return_url']
    except (ValueError, KeyError):
        return 'Invalid request state', httplib.BAD_REQUEST

    if client_csrf != server_csrf:
        return 'Invalid request state', httplib.BAD_REQUEST

    flow = _get_flow_for_token(server_csrf)

    if flow is None:
        return 'Invalid request state', httplib.BAD_REQUEST

    # Exchange the auth code for credentials.
    try:
        credentials = flow.step2_exchange(code)
    except client.FlowExchangeError as exchange_error:
        current_app.logger.exception(exchange_error)
        content = 'An error occurred: {0}'.format(exchange_error)
        return content, httplib.BAD_REQUEST

    # Save the credentials to the storage.
    self.storage.put(credentials)

    if self.authorize_callback:
        self.authorize_callback(credentials)

    return redirect(return_url)


@app.route("/github_callback")
def github_callback():
    github = OAuth2Session(github_client_id, state=session['github_oauth_state'])
    github_token = github.fetch_token(TOKEN_URL, client_secret=github_client_secret,
                               authorization_response=request.url)
    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    session['github_oauth_token'] = github_token
    github = OAuth2Session(github_client_id, token=session['github_oauth_token'])
    username = github.get('https://api.github.com/user').json()['login']
    session['username'] = username
    return redirect(url_for('.home'))


@app.route("/github_logout", methods=['GET'])
def github_logout():
    if 'github_oauth_token' in session: del session['github_oauth_token']
    if 'state' in session: del session['state']
    if 'username' in session: del session['username']
    return redirect(url_for('.home'))


@app.route("/google_logout", methods=['GET'])
def google_logout():
    session.clear()
    return redirect(url_for('.home'))


@app.route('/settings')
@oauth2.required
def settings():
    return flask.render_template('settings.html')


@app.route('/redwood')
def redwood():
    return flask.render_template('redwood.html', page_title='Redwood')


@app.route('/boardwalk')
def boardwalk():
    return flask.render_template('boardwalk.html', page_title='Boardwalk')


@app.route('/spinnaker')
def spinnaker():
    return flask.render_template('spinnaker.html', page_title='Spinnaker')


@app.route('/about')
def about():
    return flask.render_template('about.html', page_title='About')


@app.route('/help')
def help():
    return flask.render_template('help.html', page_title='Help')


@app.route('/file_browser')
def file_browser():
    return flask.render_template('file_browser.html', page_title='File Browser')


@app.route('/')
def home():
    """Home page logic."""
    # Google OAuth things.
    if 'google_oauth2_credentials' in session:
        google_credentials = client.OAuth2Credentials.from_json(session['google_oauth2_credentials'])
        session['google_oauth_token'] = google_credentials.token_response['access_token']
        access_token = google_credentials.get_access_token().access_token
        #access_token = google_credentials.access_token
        scopes = ' '.join(google_credentials.scopes)
        #requests.put("http://0.0.0.0:8543/admin/scopes/%s" % 'dkilgore', auth=('admin', 'secret'), params=scopes)
        cmd = "curl -k -XPUT %s -u admin:secret -d\"s3.upload s3.download\""
        if not subprocess.call(shlex.split(cmd), shell=True) == 1:
            print("WARNING")
        id_token = google_credentials.id_token
        if google_credentials.access_token_expired:
            return redirect(url_for('google_callback'))
    google_logged_in = True if 'google_oauth_token' in session else False
    #google_authorization_url = url_for('oauth2.authorize', return_url=url_for('home', _external=True))
    google_authorization_url = url_for('google_authorize_view', return_url=url_for('home', _external=True))

    return flask.render_template('index.html', page_title='Analysis Core',
        google_logged_in=google_logged_in,
        google_authorization_url=google_authorization_url)


if __name__ == '__main__':
    if args.oauth_environ:
        print("Warning: needed to set OAUTHLIB_INSECURE_TRANSPORT=1 environment variable, via os.environ in Python.")
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=DEBUG, port=args.port)
