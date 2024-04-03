from flask_socketio import SocketIO
from flask import Flask, app
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from models.model import db
import os
from dotenv import load_dotenv, dotenv_values
load_dotenv()

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS')
    app.config['UPLOAD_FOLDER'] =  os.getenv('UPLOAD_FOLDER')
    app.config['ALLOWED_EXTENSIONS'] = os.getenv('ALLOWED_EXTENSIONS')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    db.init_app(app)
    migrate = Migrate(app, db)
    jwt = JWTManager(app)
    socketio = SocketIO(app)
    return app, socketio