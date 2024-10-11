from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_migrate import Migrate
from models import db, User
import bcrypt
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jwtproyect.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Cambiar por una clave más segura

db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# Configuración de CORS para permitir solicitudes desde http://localhost:3000
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

#Registro
@app.route('/signup', methods=['POST'])
def signup():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    # Verifica si el usuario ya existe
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"msg": "User already exists"}), 409

    # Encripta la contraseña antes de guardarla
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=email)
    return jsonify(token=access_token), 201

# Inicio de sesión
@app.route('/login', methods=['POST'])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    user = User.query.filter_by(email=email).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        access_token = create_access_token(identity=email)
        return jsonify(token=access_token), 200

    return jsonify({"msg": "Bad email or password"}), 401

# Ruta protegida
@app.route('/private', methods=['GET'])
@jwt_required()
def private():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True, port=3001)
