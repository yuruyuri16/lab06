from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from functools import wraps

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta_de_JWT'
jwt = JWTManager(app)

API_KEY = 'tu_API_key_secreta'


def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get('X-API-KEY') != API_KEY:
            return jsonify({'error': 'API KEY inválida'}), 401
        return f(*args, **kwargs)
    return decorated


@app.route('/group01')
@jwt_required()
@api_key_required
def group01():
    return jsonify({'result': 'este es el grupo 01'})


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username == 'usuario' and password == 'contraseña':
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token})
    return jsonify({'error': 'Usuario o contraseña inválidos'}), 401


@app.route('/group02')
def group02():
    return jsonify({'result': 'este es el grupo 02'})


@app.route('/group03')
def group03():
    return jsonify({'result': 'este es el grupo 03'})


@app.route('/group04')
def group04():
    return jsonify({'result': 'este es el grupo 04'})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
