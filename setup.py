from main import app, db, Roles, Users, UserRoles


def initialSetup():
    admin = Roles(name='ADMIN',description='ADMIN FOR USER ACCOUNTS')
    stdUser = Roles(name='STDUSER',description='STANDARD APPLICATION USER')
    db.session.add(admin)
    db.session.add(stdUser)
    admin_role_id = Roles.query.filter(Roles.name == 'ADMIN').first().id
    stduser_role_id_role_id =Roles.query.filter(Roles.name == 'STDUSER').first().id
    
    adminUser = Users(username='admin',password='password')
    db.session.add(adminUser)
    db.session.commit()

    print(adminUser)
    adminUserRole = UserRoles(user_id=adminUser.id,role_id=admin_role_id)
    
    db.session.add(adminUserRole)
    db.session.commit()


with app.app_context():
    initialSetup()
    

    