#flask --app main run --debug
from sqlalchemy import exc
from flask import Flask, request, abort, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import json

admin_role_id = 0
stduser_role_id = 0

app = Flask(__name__)
CORS(app, support_credentials=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.users"
app.config["SECRET_KEY"] = "abc"
db = SQLAlchemy()
 
login_manager = LoginManager()
login_manager.init_app(app)
db.init_app(app)

@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    roles = db.relationship('UserRoles', backref='users', lazy='dynamic')

class Roles(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    users = db.relationship('UserRoles', backref='roles', lazy='dynamic')
    
class UserRoles(db.Model):
    __tablename__ = 'userRoles'
    id = db.Column(db.Integer, primary_key = True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))


with app.app_context():
    db.create_all()
    try:
        admin_role_id = Roles.query.filter(Roles.name == 'ADMIN').first().id
        stduser_role_id = Roles.query.filter(Roles.name == 'STDUSER').first().id
    except:
        print("FAILED")
  

data = open('./programText/ApiErrorMessages.json')
errorResponses = json.load(data)

@app.route("/register", methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    try:
        username = request.json['username']
        password = request.json['password']
        new_user = Users(username=username,password=password)
        db.session.add(new_user)
        db.session.commit()
        db.session.add(UserRoles(user_id=new_user.id,role_id=stduser_role_id))
        db.session.commit()
        return  {
            "username": username,
            "admin":False,
            "authenticated": True
        }
    except exc.IntegrityError:
        return handleErrorResponse('duplicateAccount',403)
    # except:
    #     return handleErrorResponse('unhandledError',500)
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
@app.route("/login", methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    #try:
        username = request.json['username']
        password = request.json['password']
        user = Users.query.filter_by(username=username).first()
        if user:
            if user.password == password:
                if login_user(user):                  
                    rolesList = []
                    print(user.roles.all()[0])
                    user_roles = db.session.query(UserRoles).join(Users.roles).filter(Users.id==user.id).all()
                    for role in user_roles:
                        rolesList.append(db.session.query(Roles.name).filter(Roles.id == role.role_id).first().name)
                
                    print(rolesList)
                    #     rolesList.append(role.name)
                    # print(rolesList)
                    return{'id': user.id, 'username': username, 'roles': rolesList}
                else:
                    return handleErrorResponse('inactiveAccount',401)
            else:
                return handleErrorResponse('incorrectPassword',401)
        else:
            return handleErrorResponse('userNotFound',404)
    # except:
    #     return handleErrorResponse('unhandledError',500)
    
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

