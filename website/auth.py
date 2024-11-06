from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from .models import User, Token
from . import db
from flask_login import login_user, login_required, logout_user, current_user
import hashlib, random, time, secrets, string, re
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in succesfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
        
        flash('Email or password incorrect', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

def is_valid_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):  # At least one letter
        return False
    if not re.search(r"\d", password):  # At least one digit
        return False
    return True

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
        elif not is_valid_password(password1):
            flash('Password must be at least 8 characters long and include at least one letter and one number', category='error')
        else:
            hashed_password = generate_password_hash(password1)
            new_user = User(email=email, username=username, password=hashed_password)
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
        salt = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10))

        token = token + hashlib.sha256((token + salt).encode()).hexdigest()  # Generate a secure token
        new_token = Token(user_id=user.id, token=token)

        db.session.add(new_token)
        db.session.commit()
    flash('A recovery email has been sent to your address!', 'success')

    return redirect(url_for('auth.login'))  # Redirect to the login page after submission

# Reset Password Route
@auth.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_entry = Token.query.filter_by(token=token).first()
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if token_entry:

            expiration_time = token_entry.created_at + datetime.timedelta(minutes=1)
            if datetime.datetime.utcnow() > expiration_time:
                flash('The reset link has expired. Please request a new one.', 'error')
                db.session.delete(token_entry)  # Remove the expired token
                db.session.commit()
                return render_template('reset_password.html', token=token, user=current_user)

            if not is_valid_password(new_password):
                flash('Password must be at least 8 characters long and include at least one letter and one number', category='error')
            else:
                user = token_entry.user
                user.password = generate_password_hash(new_password)

                # Removing token from database
                db.session.delete(token_entry)

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
    
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    # Check if current password is correct
    if not check_password_hash(current_user.password, current_password):
        flash('Incorrect password, try again.', category='error')

    # Check if new password matches confirmation
    elif new_password != confirm_password:
        flash('Passwords do not match', 'error')

    elif not is_valid_password(new_password):
        flash('Password must be at least 8 characters long and include at least one letter and one number', category='error')

    else:
        # Update the password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully', 'success')
        return redirect(url_for('views.profile', user_id=current_user.id))
    
    return redirect(url_for('views.profile', user_id=current_user.id))

