from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from datetime import datetime

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    username = db.Column(db.String(150))
    description = db.Column(db.String(500), nullable=True)
    image = db.Column(db.String(150), default='default-icon.png')
    role = db.Column(db.String(150), default='user')
    notes = db.relationship('Note')

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(150), unique=True, nullable=False)
    user = db.relationship('User', backref='tokens')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)