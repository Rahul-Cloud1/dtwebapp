# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""
import json
import os
import sys
import re

import requests
import secrets

from flask import render_template, redirect, request, url_for, flash
from flask_login import (
    current_user,
    login_user,
    logout_user, login_required
)

from apps import db, login_manager, config
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm, CreateDemoForm
from apps.authentication.models import Users

from apps.authentication.util import verify_pass
from oauthlib.oauth2 import WebApplicationClient

# OAuth 2 client setup
client = WebApplicationClient(os.environ.get('GOOGLE_CLIENT_ID'))


def get_google_provider_cfg():
    return requests.get(os.environ.get('GOOGLE_DISCOVERY_URL')).json()


@blueprint.route('/')
def route_default():
    return render_template('main/index.html')


@blueprint.route('/about_us')
def about_us():
    return render_template('main/about_us.html')


@blueprint.route('/contact_us')
def contact_us():
    return render_template('main/contact_us.html')


# Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = Users.query.filter_by(username=username).first()

        # Check the password
        if user and verify_pass(password, user.password):
            login_user(user)
            return redirect(url_for('authentication_blueprint.demo'))

        # Something (user or pass) is not ok
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/google_register', methods=['GET', 'POST'])
def google_register():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        # Find out what URL to hit for Google login
        google_provider_cfg = get_google_provider_cfg()
        authorization_endpoint = google_provider_cfg["authorization_endpoint"]
        # Use library to construct the request for Google login and provide
        # scopes that let you retrieve user's profile from Google
        request_uri = client.prepare_request_uri(
            authorization_endpoint,
            redirect_uri=request.base_url + "/callback",
            scope=["openid", "email", "profile"],
        )
        return redirect(request_uri)


@blueprint.route("/google_register/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(os.environ.get('GOOGLE_CLIENT_ID'), os.environ.get('GOOGLE_CLIENT_SECRET')),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided
    # by Google
    # user = User(
    #     id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    # )

    # Locate user
    user = Users.query.filter_by(username=users_email).first()

    # Check the password
    if user:
        login_user(user)
        return redirect(url_for('authentication_blueprint.demo'))
    else:
        password = secrets.token_hex(16)
        print(password)
        user = Users(
            username=users_email,
            email=users_email,
            password=password
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('authentication_blueprint.demo'))


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Check username exists
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        # Delete user from session
        logout_user()

        return render_template('accounts/register.html',
                               msg='User created successfully.',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/demo', methods=('GET', 'POST'))
@login_required
def demo():
    if 'results' in request.args:
        results = eval(request.args['results'])
        success = eval(request.args['success'])
    else:
        results = {}
        success = False
    print(results, file=sys.stderr)
    print(type(results), file=sys.stderr)
    create_demo_form = CreateDemoForm()
    print(request.form, file=sys.stderr)
    print(request.method, file=sys.stderr)
    if request.method == 'POST' and create_demo_form.validate_on_submit():
        project = request.form['project']
        region = request.form['region']
        token = request.form['token']
        timeout = request.form['timeout']
        if not token:
            flash('Token is required!')
        request_payload_dict = {'project': project, 'region': region,
                                'token': token, 'action': 'create',
                                'timeout': timeout}
        flash('Please wait!, your request is in process')
        response = requests.post(
            url=config.Config.CLOUD_FN_URL,
            json=request_payload_dict
        )
        ip_regex = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if ip_regex.match(response.text):
            success = True
            results = {"Live Demo Link": f"http://{response.text}"}
            result = f"project: {project} \nregion: {region}\ntoken: {token}"
        else:
            success = False
            results = {"Error": f"Please check with support team.\n{response.text}"}
        # return render_template('main/demo.html',
        #                        success=True,
        #                        form=create_demo_form, results=results)
        # return redirect('authentication_blueprint.demo', results=results)
        return redirect(url_for('authentication_blueprint.demo', success=success, create_demo_form=create_demo_form,
                                results=results))

    return render_template('main/demo.html',
                           create_demo_form=create_demo_form, success=success, results=results)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login'))


# Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('home/page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500
