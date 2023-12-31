from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()], render_kw={
        "placeholder": "Enter your name"})
    email = StringField('Email Address', validators=[DataRequired()], render_kw={
        "placeholder": "Enter an email address"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={
        "placeholder": "Enter a password"})
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired()], render_kw={
        "placeholder": "Enter an email address"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={
        "placeholder": "Enter a password"})
    submit = SubmitField("Login")

class CommentForm(FlaskForm):
    text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")