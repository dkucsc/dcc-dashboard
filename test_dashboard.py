import os
import unittest
import logging
import tempfile

import flask
from oauth2client.contrib import flask_util
from requests_oauthlib import OAuth2Session
from oauth2client import client
from flask import session

import dashboard


def home():
    """Home page logic."""
    if 'google_oauth2_credentials' in session:
        google_credentials = client.OAuth2Credentials.from_json(session['google_oauth2_credentials'])
        access_token = google_credentials.get_access_token().access_token
        print("Access token: %s" % access_token)
        access_token = google_credentials.access_token
        print("Access token: %s" % access_token)
        scopes = google_credentials.scopes
        print("Scopes: %s" % scopes)
        id_token = google_credentials.id_token
        print("ID token: %s" % id_token)
        if google_credentials.access_token_expired:
            return redirect(url_for('google_callback'))
        print "GREAT"
    github_logged_in = True if 'github_oauth_token' in session else False
    google_logged_in = True if 'google_oauth_token' in session else False
    username = session['username'] if (github_logged_in and 'username' in session) else None
    github_oauth = OAuth2Session(github_client_id, redirect_uri=app_redirect_uri,
        scope=scopes)
    github_authorization_url, github_state = github_oauth.authorization_url(AUTHORIZATION_BASE_URL)
    session['github_oauth_state'] = github_state
    flow = oauth2._make_flow(return_url='http://localhost:8000/cool')
    print(flow)
    print(dir(flow))
    google_oauth = OAuth2Session(google_client_id, redirect_uri=app_redirect_uri,
        scope=scopes)
    google_authorization_url, google_state = google_oauth.authorization_url(GOOGLE_AUTHORIZATION_BASE_URL)
    session['google_oauth_state'] = google_state
    return flask.render_template('index.html', page_title='Home', username=username,
        #github_logged_in=github_logged_in, github_url=github_authorization_url, google_url=google_authorization_url)
        github_logged_in=github_logged_in, github_url=github_authorization_url, google_url="http://localhost:8000/google_callback", google_logged_in=google_logged_in)


class WinterDemoTestCase(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        #self.app = dashboard.create_app()
        print(dir(dashboard))
        self.app.add_url_rule('/', 'home', home)
        self.app.testing = True
        self.app.config['SECRET_KEY'] = 'notasecert'
        self.app.logger.setLevel(logging.CRITICAL)
        self.oauth2 = flask_util.UserOAuth2(
            self.app,
            client_id='client_idz',
            client_secret='client_secretz')

    def test_basic_github_flow(self):
        # We can go to the homepage successfully.
        with self.app.test_client() as client:
            response = client.get('/')
            print response.status_code


if __name__ == '__main__':
    unittest.main()
