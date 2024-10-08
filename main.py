#flask --app main run --debug
from sqlalchemy import exc
from flask import Flask, request, abort, jsonify
from flask_cors import CORS, cross_origin
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt 
import datetime
import json

admin_role_id = 0
stduser_role_id = 0

app = Flask(__name__)
CORS(app, support_credentials=True)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.users"
app.config["SECRET_KEY"] = "abc"
db = SQLAlchemy()

bcrypt = Bcrypt(app)
 
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
    lastLogin = db.Column(db.String(20))
    accountCreated = db.Column(db.String(20))
    roles = db.relationship('UserRoles', backref='users', lazy='dynamic')
    settings = db.relationship('UserSettings', backref='users', lazy='dynamic')


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

class UserSettings(db.Model):
    __tablename__ = "userSettings"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    appearance = db.Column(db.String(10), nullable=False)
    fontSize = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(20))

    def asDict(self):
        return {
            'appearance': self.appearance,
            'fontSize': self.fontSize,
            'name': self.name
        }

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
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(username=username,password=hashed_password,accountCreated=datetime.datetime.now().isoformat())
        db.session.add(new_user)
        db.session.commit()
        db.session.add(UserRoles(user_id=new_user.id,role_id=stduser_role_id))
        db.session.add(UserSettings(user_id=new_user.id,appearance='light',fontSize=10))
        db.session.commit()
        return  {
            "username": username,
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
            if bcrypt.check_password_hash(user.password, password):
                if login_user(user):
                    user.lastLogin = datetime.datetime.now().isoformat()
                    db.session.commit()     
                    return getUserDetails(user)
                else:
                    return handleErrorResponse('inactiveAccount',401)
            else:
                return handleErrorResponse('incorrectPassword',401)
        else:
            return handleErrorResponse('userNotFound',404)
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

@app.route('/userSettings',methods=['PUT','GET'])
@cross_origin(supports_credentials=True)
@login_required
def userSettings():
    try:
        settings = UserSettings.query.filter(UserSettings.user_id == current_user.id).first()
        if request.method == 'PUT': 
            newVal = request.json['userSettings']
            settings.appearance = newVal['appearance']
            settings.fontSize = newVal['fontSize']
            settings.name = newVal['name']
            db.session.commit()    
        return settings.asDict()
    except:
        handleErrorResponse('unhandledError',500)

@app.route('/userDetails',methods=['GET'])
@cross_origin(supports_credentials=True)
@login_required
def userDetails():
    try:
        return getUserAccreditation(db.session.query(Users).filter(Users.id == current_user.id).first())
    except:
            handleErrorResponse('unhandledError',500)

@app.route('/updatePassword',methods=['PUT'])
@cross_origin(supports_credentials=True)
@login_required
def updatePassword():
    try:
        id = request.json['id']
        oldPassword = request.json['oldPassword']
        newPassword = request.json['newPassword']
        if(current_user.id == id):
            user = Users.query.filter(Users.id==id).first()
            if(bcrypt.check_password_hash(user.password, oldPassword)):
                if(validatePassword(newPassword)):
                    hashed_password = bcrypt.generate_password_hash(newPassword).decode('utf-8')
                    user.password = hashed_password
                    db.session.commit()
                    return {"success":True}
            else:
                return handleErrorResponse('incorrectPassword',403)
        else:
            return handleErrorResponse('incorrectPermission', 401)
    except:
        return handleErrorResponse('unhandledError',500)

@app.route('/adminSettings',methods=['GET','PUT'])
@cross_origin(supports_credentials=True)
@login_required
def adminSettings():
    try:
        userRoles = getUserRoles(Users.query.filter(Users.id==current_user.id).first())
        if 'ADMIN' in userRoles:
            if request.method == 'PUT':
                print("PUT")
                return {}
            elif request.method == 'GET':
                users = Users.query.all()
                returnUsers = []
                for user in users:
                    returnUsers.append(getUserDetails(user))
                return returnUsers
        else:
            return handleErrorResponse('incorrectPermission',401)
    except:
        return handleErrorResponse('unhandledError',500)




#util functions
def handleErrorResponse(message, code):
    response = jsonify({'message': errorResponses[message]})
    response.status_code = code
    return response

def getUserAccreditation(user):
    return {'id': user.id, 'username': user.username, 'roles': getUserRoles(user)}

def getUserDetails(user):
    return {'id':user.id,'username':user.username,'accountCreated':user.accountCreated,'lastLogin':user.lastLogin,'roles':getUserRoles(user)}

def getUserRoles(user):
    rolesList = []
    user_roles = db.session.query(Roles.name).join(UserRoles).join(Users).filter(Users.id == user.id).all()
    for role in user_roles:
        rolesList.append(role[0])
    return rolesList

def validatePassword(password):
    return True

