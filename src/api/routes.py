"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

api = Blueprint('api', __name__)

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def handle_signup():
    username = request.json.get("username", None)
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    newUser = User(username = username, email = email, password = password)
    if User.query.filter_by(username = username, email = email).first() == None:
        db.session.add(newUser)
        db.session.commit()
        return jsonify("Added User"), 200
    else:
        return jsonify("That username or email is already in use"), 400

@api.route('/login', methods=['POST'])
def handle_login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = User.query.filter_by(username=username, password=password).first()
    if user is None:
        return jsonify({"msg" : "Bad username or password"}), 401
    access_token = create_access_token(identity=user.id)
    return jsonify({"token": access_token, "user_id": user.id}), 200

@api.route('/private', methods=['GET'])
@jwt_required()
def handle_private():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    return jsonify({"user_id": user.id, "username":user.username}), 200