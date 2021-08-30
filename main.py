import base64
import datetime
import functools
import hashlib
import io
import json
import os
import urllib

import flask
import pymysql
import pymysql.cursors
import pyqrcode
from werkzeug.wsgi import FileWrapper

# GLOBAL VARIABLES
HOST_URL = os.getenv('HOST_URL')

DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

AUTH_USER = os.getenv('AUTH_USER')
AUTH_PASSWORD = os.getenv('AUTH_PASSWORD')
AUTH_SECRET = os.getenv('AUTH_SECRET')
AUTH_DURATION = datetime.timedelta(hours=2)
AUTH_COOKIE = "tfma"


# DB FUNCTIONS
def log_person(nom, cognoms, telefon):
    # Connect to the database
    connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                                 database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
    with connection.cursor() as cursor:
        # Create a new record
        query = "INSERT INTO `log` (`nom`, `cognoms`, `telefon`) VALUES (%s, %s, %s)"
        cursor.execute(query, (nom, cognoms, telefon))
        connection.commit()


def setup_db():
    # Connect to the database
    connection = pymysql.connect(host=DB_HOST, user=DB_USER, password=DB_PASSWORD,
                                 database=DB_NAME, cursorclass=pymysql.cursors.DictCursor)
    with connection.cursor() as cursor:
        # Create a new record
        query = """
                CREATE TABLE IF NOT EXISTS `log` (
                    log_id INT AUTO_INCREMENT PRIMARY KEY,
                    nom VARCHAR(255) NOT NULL,
                    cognoms VARCHAR(255) NOT NULL,
                    telefon VARCHAR(255) NOT NULL,
                    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
        cursor.execute(query)
        connection.commit()


# AUTH FUNCTIONS
def salted_hash(data):
    m = hashlib.sha256()
    m.update(data)
    m.update(AUTH_SECRET)
    return m.hexdigest().decode('utf-8')


def timestamp(dt):
    return (dt - datetime.datetime(1970, 1, 1)).total_seconds()


def generate_token():
    exp = datetime.datetime.now() + AUTH_DURATION
    b_exp_b64 = base64.b64encode(str(timestamp(exp)).encode('utf-8'))
    token = '.'.join([b_exp_b64.decode('utf-8'), salted_hash(b_exp_b64)])
    return token


def is_token_valid(token):
    stoken = token.split('.')
    if len(stoken) != 2:
        return False
    exp_b64, checksum = stoken
    if checksum != salted_hash(exp_b64.encode('utf-8')):
        return False
    try:
        exp_str = base64.b64decode(exp_b64.encode('utf-8')).decode('utf-8')
        exp = float(exp_str)
    except Exception:
        return False
    return exp >= timestamp(datetime.datetime.now())

# WEB APP


app = flask.Flask(__name__)


class HTTPError(flask.Response, Exception):
    def __init__(self, status_code, *args, **kwargs):
        super(HTTPError, self).__init__(*args, **kwargs)
        self.status_code = status_code


def handle_errors(func):
    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except HTTPError as r:
            return r, r.status_code
        except Exception:
            return flask.Response("Oh no! Hi ha hagut un error en el servidor :(", status="Internal error"), 500

    return wrapped


def get_param(name, error_string):
    param = flask.request.args.get(name)
    if not param:
        raise HTTPError(400, error_string)
    return param


def get_form(name, error_string):
    param = flask.request.form.get(name)
    if not param:
        raise HTTPError(400, error_string)
    return param


# GENERADOR DE QRs
@app.route("/qr", methods=["POST"])
@handle_errors
def get_qr():
    # Get params
    nom = get_form('nom', 'Cal que donis el teu nom!')
    cognoms = get_form('cognoms', 'Cal que donis els teus cognoms!')
    telefon = get_form('telefon', 'Cal que donis el teu telefon!')
    # Build data
    data = {
        "nom": nom,
        "cognoms": cognoms,
        "telefon": telefon
    }
    data_json = json.dumps(data)
    data_b64 = base64.b64encode(data_json.encode('utf-8')).decode('utf-8')
    # Build url
    result_params = urllib.urlencode({"data": data_b64})
    endpoint = "?".join(['benvingut', result_params])
    url = "/".join([HOST_URL, endpoint])
    # Build QR code
    code = pyqrcode.create(url)
    img_io = io.BytesIO()
    code.png(img_io, scale=6)
    # Return the image
    img_io.seek(0)
    w = FileWrapper(img_io)
    return flask.Response(w, mimetype='image/png', direct_passthrough=True)


# LOGGEJADOR (cal estar registrat per loggejar)
@app.route("/benvingut")
@handle_errors
def benvingut():
    # Get params
    data_b64 = get_param('data', 'No hi ha dades :(')
    data = json.loads(base64.b64decode(data_b64.encode('utf-8')).decode('utf-8'))

    # Check authentication
    auth_token = flask.request.cookies.get(AUTH_COOKIE)
    if not auth_token or not is_token_valid(auth_token):
        raise HTTPError(403, "Has d'estar registrat!")

    # Build registration form
    with open("./registra.html", "rt") as f:
        html = f.read()
    data['data'] = data_b64
    data['host_url'] = HOST_URL
    html = html.format(**data)

    return flask.Response(html, mimetype='text/html')


@app.route("/registra", methods=['POST'])
@handle_errors
def registra():
    # Get params
    data_b64 = get_form('data', 'No hi ha dades :(')
    data = json.loads(base64.b64decode(data_b64.encode('utf-8')).decode('utf-8'))

    # Check authentication
    auth_token = flask.request.cookies.get(AUTH_COOKIE)
    if not auth_token or not is_token_valid(auth_token):
        raise HTTPError(403, "Has d'estar registrat!")

    # Log person
    log_person(**data)

    # Build confirmation form
    with open("./confirma.html", "rt") as f:
        html = f.read()
    data['data'] = data_b64
    html = html.format(**data)

    return flask.Response(html, mimetype='text/html')


# REGISTRE
@app.route("/login", methods=['POST'])
@handle_errors
def login():
    user = get_form('user', 'Cal un usuari!')
    password = get_form('password', 'Cal una contrassenya!')

    if user != AUTH_USER or password != AUTH_PASSWORD:
        raise HTTPError(401, "Usuari i/o contrassenya incorrectes!")

    expire_date = datetime.datetime.now() + AUTH_DURATION
    token = generate_token()

    resp = flask.make_response("Salutacions!")
    resp.set_cookie(AUTH_COOKIE, token, expires=expire_date)

    return resp


# LOGOUT
@app.route("/logout")
@handle_errors
def logout():
    resp = flask.make_response("Comiats!")
    resp.set_cookie(AUTH_COOKIE, None, expires=0)
    return resp


# SETUP DB
@app.route("/setup", methods=['POST'])
@handle_errors
def setup():
    # Check authentication
    auth_token = flask.request.cookies.get(AUTH_COOKIE)
    if not auth_token or not is_token_valid(auth_token):
        raise HTTPError(403, "Has d'estar registrat!")

    # Setup db
    setup_db()
    resp = flask.Response('Tot preparat!')
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
