from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.google import make_google_blueprint, google
from flask import session, redirect, render_template, Blueprint
from flask_dance.consumer import OAuth2ConsumerBlueprint

from CTFd import utils
from CTFd.models import db, Users
from CTFd.utils import set_config
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user


def load(app):
    authentication_url_prefix = '/auth'
    plugin = Blueprint(
        'CTFd-OAuth2',
        __name__,
        static_folder='assets',
        template_folder='templates'
    )

    @plugin.route('apps', methods=['GET'])
    def auth_apps():
        return render_template('auth.html')

    app.register_blueprint(plugin, url_prefix=authentication_url_prefix)

    ##################
    # User Functions #
    ##################
    def retrieve_user_from_database(email):
        user = Users.query.filter_by(email=email).first()
        if user:
            log('logins', '[{date}] {ip} - ' + email + ' - OAuth2 bridged user found')
            return user

    def create_user(email, display_name):
        with app.app_context():
            log('logins', '[{date}] {ip} - ' + email + ' - No OAuth2 bridged user found, creating user')
            user = Users(email=email, name=display_name.strip())
            db.session.add(user)
            db.session.commit()
            return Users.query.filter_by(email=email).first()

    def create_or_get_user(email, display_name):
        user = retrieve_user_from_database(email)
        if user:
            return user
        else:
            return create_user(email, display_name)

    ##########################
    # Provider Configuration #
    ##########################
    github = make_github_blueprint(
        login_url='/github',
        client_id=utils.get_app_config('OAUTHLOGIN_GITHUB_CLIENT_ID'),
        client_secret=utils.get_app_config('OAUTHLOGIN_GITHUB_CLIENT_SECRET'),
        redirect_url=f'{authentication_url_prefix}/github/confirm'
    )

    mlh = OAuth2ConsumerBlueprint(
        'mlh',
        __name__,
        client_id=utils.get_app_config('OAUTHLOGIN_MLH_CLIENT_ID'),
        client_secret=utils.get_app_config('OAUTHLOGIN_MLH_CLIENT_SECRET'),
        base_url='https://my.mlh.io/',
        token_url='https://my.mlh.io/oauth/token',
        authorization_url='https://my.mlh.io/oauth/authorize',
        redirect_url=f'{authentication_url_prefix}/mlh/confirm'
    )

    google = make_google_blueprint(
        login_url='/google',
        scope=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
        client_id=utils.get_app_config('OAUTHLOGIN_GOOGLE_CLIENT_ID'),
        client_secret=utils.get_app_config('OAUTHLOGIN_GOOGLE_CLIENT_SECRET'),
        redirect_url=f'{authentication_url_prefix}/google/confirm'
    )

    def get_github_user():
        user_info = github.session.get('/user').json()
        return {
            'email': user_info['email'],
            'display_name': user_info['name']
        }

    def get_mlh_user():
        user_info = mlh.session.get('/api/v3/user.json').json()
        user_info = user_info['data']
        return {
            'email': user_info['email'],
            'display_name': ' '.join([user_info['first_name'], user_info['last_name']])
        }

    def get_google_user():
        user_info = google.session.get('/oauth2/v2/userinfo').json()
        return {
            'email': user_info['email'],
            'display_name': user_info['name']
        }

    provider_users = {
        'github': get_github_user,
        'mlh': get_mlh_user,
        'google': get_google_user
    }

    #######################
    # Blueprint Functions #
    #######################
    @github.route('/<string:auth_provider>/confirm', methods=['GET'])
    @mlh.route('/<string:auth_provider>/confirm', methods=['GET'])
    @google.route('/<string:auth_provider>/confirm', methods=['GET'])
    def confirm_auth_provider(auth_provider):
        if auth_provider not in provider_users:
            return redirect('/')

        provider_user = provider_users[auth_provider]()
        session.regenerate()

        if provider_user:
            user = create_or_get_user(
                email=provider_user['email'],
                display_name=provider_user['display_name']
            )
            if user:
                login_user(user)

        return redirect('/')

    app.register_blueprint(github, url_prefix=authentication_url_prefix)
    app.register_blueprint(mlh, url_prefix=authentication_url_prefix)
    app.register_blueprint(google, url_prefix=authentication_url_prefix)

    ###############################
    # Application Reconfiguration #
    ###############################
    # ('', 204) is "No Content" code
    set_config('registration_visibility', False)
    app.view_functions['auth.login'] = lambda: redirect(f'{authentication_url_prefix}/apps')
    app.view_functions['auth.register'] = lambda: ('', 204)
    app.view_functions['auth.reset_password'] = lambda: ('', 204)
    app.view_functions['auth.confirm'] = lambda: ('', 204)
