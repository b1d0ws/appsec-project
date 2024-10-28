from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for, current_app, render_template_string
from flask_login import login_required, current_user
from .models import Note, User
from . import db
import json, os, requests
from sqlalchemy import text

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

    if request.method == 'POST':
        description = request.form.get('description')

        if description:
            current_user.description = description
            db.session.commit()
            flash('Description updated successfully!', 'success')
        else:
            flash('Description cannot be empty!', 'error')

    return render_template("profile.html", user=user)

@views.route('/delete-note', methods=['POST'])
@login_required
def delete_node():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note: 
        db.session.delete(note)
        db.session.commit()
    return jsonify({})

# Upload Image Route
@views.route('/upload_image', methods=['POST'])
def upload_image():

    if 'profile_image' in request.files:
        file = request.files['profile_image']
        filename = file.filename

        upload_folder = current_app.config['UPLOAD_FOLDER']

        # Save the file
        file.save(os.path.join(upload_folder, filename))

        # print(filename)
        
        current_user.image = filename
        db.session.commit()

        flash('Profile image updated successfully', 'success')

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
            user.role = new_role.encode('utf-8', 'ignore').decode('utf-8')

        db.session.commit()

        return jsonify({"message": f"User {username} updated to role {new_role}"}), 200

    if current_user.role != 'administrator':
        return "Access Denied", 403
    
    query = request.args.get('query', '')
    notes = []

    if query:
        sql = text(f"SELECT * FROM note WHERE data LIKE '%{query}%'")
        notes = db.session.execute(sql).fetchall()

    rendered_notes = [render_template_string(note.data) for note in notes]

    return render_template("admin.html", user=current_user, query=query, notes=rendered_notes)

@views.route('/admin/fetch-url', methods=['POST'])
@login_required
def fetch_url():
    if current_user.role != 'administrator':
        return "Access Denied", 403

    url = request.form.get('url')
    
    try:
        response = requests.get(url)
        return response.content
    except Exception as e:
        return jsonify({"error": str(e)}), 400
