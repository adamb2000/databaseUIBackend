#flask --app main run --debug
from sqlalchemy import exc
from flask import Flask, request, abort, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import json

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

data = open('./programText/ApiErrorMessages.json')
errorResponses = json.load(data)

@app.route("/register", methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    try:
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
    except exc.IntegrityError:
        return handleErrorResponse('duplicateAccount',403)
    except:
        return handleErrorResponse('unhandledError',500)
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
@app.route("/login", methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    try:
        username = request.json['username']
        password = request.json['password']
        user = Users.query.filter_by(username=username).first()
        if user:
            if user.password == password:
                if login_user(user):
                    response = jsonify({'id': user.id, 'username': username})
                    response.status_code = 200
                    return response
                else:
                    return handleErrorResponse('inactiveAccount',403)
            else:
                return handleErrorResponse('incorrectPassword',403)
        else:
            return handleErrorResponse('userNotFound',403)
    except:
        return handleErrorResponse('unhandledError',500)
    
@app.route('/logout',methods=['POST'])
@cross_origin(supports_credentials=True)
@login_required
def logout():
    logout_user()
    response = jsonify({'auth':False})
    response.status_code = 200
    return response

def handleErrorResponse(message, code):
    response = jsonify({'message': errorResponses[message]})
    response.status_code = code
    return response