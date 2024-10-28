from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, current_app, render_template_string, session
from flask_login import login_required, current_user
from .models import Note, User
from . import db
import json, os, requests, re, socket
from sqlalchemy import text
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network

views = Blueprint('views', __name__)

@views.route('/', methods=['GET', 'POST'])
def home():  
    return render_template("home.html", user=current_user)


@views.route('/notes', methods=['GET', 'POST'])
@login_required
def notes():
    if request.method == 'POST':
        note = request.form.get('note')

        if len(note) < 1:
            flash('Note is too short!', category='error')
        else:
            new_note = Note(data=note, user_id=current_user.id)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')

    return render_template("notes.html", user=current_user)


@views.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id):

    user = User.query.get_or_404(user_id)

    csrf_token = os.urandom(16).hex()
    session['csrf_token'] = csrf_token

    if request.method == 'POST':
        description = request.form.get('description')

        if description:
            current_user.description = description
            db.session.commit()
            flash('Description updated successfully!', 'success')
        else:
            flash('Description cannot be empty!', 'error')

    return render_template("profile.html", csrf_token=csrf_token, user=user)

@views.route('/delete-note', methods=['POST'])
@login_required
def delete_node():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    
    if note:
        # Checking authorization
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
            return jsonify({"message": "Note successfully deleted"}), 200
    return jsonify({"message": "You cannot delete this note"}), 403

# Upload Image Route
@views.route('/upload_image', methods=['POST'])
@login_required
def upload_image():

    ALLOWED_EXTENSIONS = ['png', 'jpg', 'jpeg']

    if 'profile_image' in request.files:
        file = request.files['profile_image']
        # Using secure_filename to prevent path traversal
        filename = secure_filename(file.filename)

        # Checking extension
        extension = filename.rsplit('.', 1)[1].lower()

        upload_folder = current_app.config['UPLOAD_FOLDER']

        if extension in ALLOWED_EXTENSIONS:
            # Save the file
            file.save(os.path.join(upload_folder, filename))
        
            current_user.image = filename
            db.session.commit()

            flash('Profile image updated successfully', 'success')

        else:
            flash('Something went wrong!', 'error')

    return redirect(url_for('views.profile', user_id=current_user.id))


@views.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():

    if request.method == 'POST':

        data_str = request.data
        data = json.loads(data_str)
  
        username = data.get('user')
        new_role = data.get('role')

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        if not user:
            return jsonify({"message": "User not found"}), 404
        
        if new_role.lower() == 'administrator':
            return jsonify({"message": "You cannot update the role to 'administrator'"}), 404
        else:
            user.role = new_role

        db.session.commit()

        return jsonify({"message": f"User {username} updated to role {new_role}"}), 200

    if current_user.role != 'administrator':
        return "Access Denied", 403
    
    query = request.args.get('query', '')
    notes = []

    if query:
        sql = text("SELECT * FROM note WHERE data LIKE :query")
        notes = db.session.execute(sql, {'query': f'%{query}%'}).fetchall()

    return render_template("admin.html", user=current_user, query=query, notes=notes)

@views.route('/admin/fetch-url', methods=['POST'])
@login_required
def fetch_url():
    if current_user.role != 'administrator':
        return "Access Denied", 403

    '''
    TRUSTED_DOMAINS = ["example.com", "another-trusted-domain.com"]

    hostname = parsed_url.hostname
    if hostname not in TRUSTED_DOMAINS:
        return jsonify({"error": "Access to this host is restricted"}), 403
    '''

    FORBIDDEN_IP_RANGES = [
    ip_network("127.0.0.0/8"),        # Loopback
    ip_network("10.0.0.0/8"),         # Private
    ip_network("172.16.0.0/12"),      # Private
    ip_network("192.168.0.0/16"),     # Private
    ip_network("169.254.0.0/16"),     # Link-local
    ip_network("::1/128"),            # IPv6 loopback
    ip_network("fc00::/7"),           # IPv6 unique local
    ip_network("fe80::/10")           # IPv6 link-local
]
        
    url = request.form.get('url')
    parsed_url = urlparse(url)

    # Validate URL scheme
    if parsed_url.scheme not in ["http", "https"]:
        return jsonify({"error": "Invalid URL scheme"}), 400

    # Validate host and avoid private IPs
    hostname = parsed_url.hostname
    if re.match(r"^(localhost|127\.|0\.0\.0\.0|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01]))", hostname):
        return jsonify({"error": "Access to this host is restricted"}), 403
    
    try:

        # Resolve hostname to an IP and validate it
        resolved_ip = ip_address(socket.gethostbyname(hostname))

        # Check if the resolved IP falls within forbidden ranges
        if any(resolved_ip in net for net in FORBIDDEN_IP_RANGES):
            return jsonify({"error": "Access to this IP is restricted"}), 403

        response = requests.get(url)
        return response.content
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    
