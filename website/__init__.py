from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager

db = SQLAlchemy()
DB_NAME = "database.db"

# This will start our application
def create_app():
    app = Flask(__name__)

    # Secret Key will be used to generate the tokens
    app.config['SECRET_KEY'] = 'secretkey'

    # Configuring database
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    # Defining the uploade folder for user images
    app.config['UPLOAD_FOLDER'] = 'website/static/userimages/'

    # Defining blueprints to track routes
    from .views import views
    from .auth import auth
    
    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Note

    create_database(app)

    login_manager = LoginManager()
    # If user is not logged in the user will see login page
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('website/'+ DB_NAME):
        with app.app_context():
            db.create_all()
        print("Created Database!")