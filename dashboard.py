"""
TODO:
    - Make it so that you don't need to start the command line with
      "OAUTHLIB_INSECURE_TRANSPORT=1"

    - Consider port forwarding ec2 security group port settings, so that the
      redirect from Github works correctly.
"""


import os, sys
import logging
from argparse import ArgumentParser
import subprocess, shlex

import flask
from flask import request, session, redirect, url_for
from flask.json import jsonify
import requests
from requests_oauthlib import OAuth2Session
from oauth2client.contrib.flask_util import UserOAuth2
from oauth2client import client
from oauth2client.contrib import dictionary_storage
from oauth2client.contrib.flask_util import _CREDENTIALS_KEY, _DEFAULT_SCOPES
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
if DEBUG: app.logger.setLevel(logging.DEBUG)
app.config['GOOGLE_OAUTH2_CLIENT_ID'] = '872012202875-cjhcvg8t6al188dk122hlfnogqdl8bt2.apps.googleusercontent.com'
app.config['GOOGLE_OAUTH2_CLIENT_SECRET'] = google_client_secret
app.secret_key = os.urandom(24)
if DEBUG:
    from flask_debugtoolbar import DebugToolbarExtension
    toolbar = DebugToolbarExtension(app)
#github_oauth2 = UCSCUserOAuth2(app, client_id='7156cfa0c982a6621530', client_secret=github_client_secret, blueprint_name='github')
oauth2 = UserOAuth2(app, client_id='872012202875-cjhcvg8t6al188dk122hlfnogqdl8bt2.apps.googleusercontent.com', client_secret=google_client_secret)


@app.route("/oauth2callback")
def google_callback():
    """The view that gets hit after a successful login at the Google OAuth 2.0
    server."""
    flow = oauth2._make_flow(return_url=url_for('home', _external=True))
    if 'code' not in request.args:
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        session['credentials'] = credentials.to_json()
        return redirect(url_for('home'))


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


@app.route("/file_browser", methods=['GET'])
def file_browser():
    return flask.render_template('file_browser.html')


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


@app.route('/oauth2callback')
def callback2():
    return 'david'
    flow = oauth2._make_flow(
        #client_id=google_client_id,
        #client_secret=google_client_secret,
        #return_url=url_for('oauth2callback', _external=True))
        return_url=url_for('home', _external=True))
        #include_granted_scopes=True)
    if 'code' not in request.args:
        auth_uri = flow.step1_get_authorize_url()
        return redirect(auth_uri)
    else:
        auth_code = request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        session['credentials'] = credentials.to_json()
        return redirect(url_for('home'))


@app.route('/settings')
@oauth2.required
def settings():
    return flask.render_template('settings.html')


@app.route('/')
def home():
    """Home page logic."""
    # Github OAuth things.
    #github_logged_in = True if 'github_oauth_token' in session else False
    #username = session['username'] if (github_logged_in and 'username' in session) else None
    #github_oauth = OAuth2Session(github_client_id,
    #    redirect_uri=app_redirect_uri, scope=[])
    #github_authorization_url, github_state = github_oauth.authorization_url(AUTHORIZATION_BASE_URL)
    #github_authorization_url = url_for('oauth2.authorize', return_url=url_for('github_callback', _external=True))
    #session['github_oauth_state'] = github_state

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
    google_authorization_url = url_for('oauth2.authorize', return_url=url_for('home', _external=True))

    return flask.render_template('index.html', page_title='Analysis Core',
        #username=username,
        #github_logged_in=github_logged_in,
        #github_authorization_url=github_authorization_url,
        google_logged_in=google_logged_in,
        google_authorization_url=google_authorization_url)


if __name__ == '__main__':
    print args.oauth_environ
    if args.oauth_environ:
        print("Warning: needed to set OAUTHLIB_INSECURE_TRANSPORT=1 environment variable, via os.environ in Python.")
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=DEBUG, port=args.port)
