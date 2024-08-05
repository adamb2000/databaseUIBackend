#flask --app main run --debug
from flask import Flask, request, abort
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user

app = Flask(__name__)
CORS(app, support_credentials=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.users"
app.config["SECRET_KEY"] = "abc"
db = SQLAlchemy()
 
login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

with app.app_context():
    db.create_all()

@app.route("/register", methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    username = request.json['username']
    password = request.json['password']
    user = Users(username=username,password=password)
    db.session.add(user)
    db.session.commit()
    return  {
        "username": username,
        "token": "token123",
        "authenticated": True
    }
 
@app.route("/login", methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    username = request.json['username']
    password = request.json['password']
    user = Users.query.filter_by(username=username).first()
    print(user)
    if user.password == password:
        login_user(user)
        return {
            "auth":True
        }
    else:
        abort(403)
