# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectMultipleField, SubmitField, SelectField
from wtforms.validators import Email, DataRequired, InputRequired


# login and registration


class LoginForm(FlaskForm):
    username = StringField('Username',
                           id='username_login',
                           validators=[DataRequired()])
    password = PasswordField('Password',
                             id='pwd_login',
                             validators=[DataRequired()])


class CreateAccountForm(FlaskForm):
    username = StringField('Username',
                           id='username_create',
                           validators=[DataRequired()])
    email = StringField('Email',
                        id='email_create',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password',
                             id='pwd_create',
                             validators=[DataRequired()])


class CreateDemoForm(FlaskForm):
    # region = SelectField(label='Region',
    #                      choices=[('asia-east2', 'Hong Kong'),
    #                               ('asia-southeast1', 'SingaPore'),
    #                               ('europe-west3', 'Frankfurt'),
    #                               ('us-east1', 'US East'),
    #                               ('asia-south1', 'Mumbai')],
    #                      validators=[InputRequired(message=None)]
    #                      )
    region = SelectField(label='Region',
                         choices=[('asia-southeast1', 'Singapore'),
                                  ('us-east1', 'US East')],
                         validators=[InputRequired(message=None)]
                         )
    project = SelectField(label='Project',
                          choices=[('Project-1', 'CostaHouse'), ('Project-2', 'Project-2')],
                          validators=[InputRequired(message=None)])
    token = PasswordField('Token',
                          validators=[DataRequired()])
    timeout = SelectField(label='TimeOut', choices=[('15', '15 Min'), ('30', '30 Min')],
                          validators=[InputRequired(message=None)])
    triggerDemo = SubmitField(label='Trigger Demo')
