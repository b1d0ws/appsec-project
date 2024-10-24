from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User, Token
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import hashlib, random, time

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if user.password == password:
                flash('Logged in succesfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email alreadye exists', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters', category='error')
        elif len(username) < 2:
            flash('First name must be greater than 1 characters', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1) < 5:
            flash('Password must be at least 5 characters', category='error')
        else:
            new_user = User(email=email, username=username, password=password1)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))
            

    return render_template("sign_up.html", user=current_user)

# Forgot Password Route
@auth.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form.get('forgot-email')
    
    user = User.query.filter_by(email=email).first()

    # Checking if user exists
    if user:
        token = str(user.id)
        random.seed(int(time.time()) * 1000)
        salt = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10))
        token = token + hashlib.sha256((token + salt).encode()).hexdigest()  # Generate a secure token
        new_token = Token(user_id=user.id, token=token)
        db.session.add(new_token)
        db.session.commit()
        flash('A recovery email has been sent to your address!', 'success')
    else:
        flash('Email address not found!', 'error')

    return redirect(url_for('auth.login'))  # Redirect to the login page after submission

# Reset Password Route
@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_entry = Token.query.filter_by(token=token).first()
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if token_entry:
            user = token_entry.user
            user.password = new_password
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid or expired token.', 'error')
    
    return render_template('reset_password.html', token=token, user=current_user)


@auth.route('/change_password', methods=['POST'])
@login_required
def change_password():
  
    csrf_token = request.form.get('csrf_token')
    if not csrf_token or csrf_token != session.pop('csrf_token', None):
        flash('Invalid CSRF token', 'error')
        return redirect(url_for('views.profile', user_id=current_user.id))
    
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    # Check if new password matches confirmation
    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('views.profile', user_id=current_user.id))

    # Update the password
    current_user.password = new_password
    db.session.commit()
    flash('Password updated successfully', 'success')
    return redirect(url_for('views.profile', user_id=current_user.id))


