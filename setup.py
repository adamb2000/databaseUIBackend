from main import app, db, Roles, Users, UserRoles, UserSettings
from flask_bcrypt import Bcrypt 
bcrypt = Bcrypt(app)

def initialSetup():
    admin = Roles(name='ADMIN',description='ADMIN FOR USER ACCOUNTS')
    stdUser = Roles(name='STDUSER',description='STANDARD APPLICATION USER')
    db.session.add(admin)
    db.session.add(stdUser)
    admin_role_id = Roles.query.filter(Roles.name == 'ADMIN').first().id
    stduser_role_id_role_id =Roles.query.filter(Roles.name == 'STDUSER').first().id
    hashed_password = bcrypt.generate_password_hash("password").decode('utf-8')
    adminUser = Users(username='admin',password=hashed_password)
    db.session.add(adminUser)
    db.session.commit()
    db.session.add(UserSettings(user_id=adminUser.id,appearance='light',fontSize=10))
    db.session.add(UserRoles(user_id=adminUser.id,role_id=admin_role_id))
    db.session.commit()


with app.app_context():
    initialSetup()
    

    