from flask import Flask, request, abort
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app, support_credentials=True)

@app.route("/login", methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    username = request.json['username']
    password = request.json['password']
    if(username == '1' and password == '2'):
        return  {
            "username": username,
            "token": "token123",
            "authenticated": True
        }
    else:
        abort(403)