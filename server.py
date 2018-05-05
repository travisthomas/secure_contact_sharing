from flask import Flask, jsonify, request
from contact import Contact
from ecdsa import SigningKey, VerifyingKey, NIST256p
from functools import wraps
from base64 import b64encode, b64decode
from os.path import exists

import sqlite3

CURVE=NIST256p

class Database(object):

    def __init__(self, path='contacts.db'):
        self.path = path
        if not exists(self.path):
            self.create_contacts_table()
            self.create_pubs_table()
            self.create_nonce_table()

    def create_contacts_table(self):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE contacts
                                (name text, address text, phone text, email text, source text, key text)''')
            conn.commit()

    def create_pubs_table(self):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE pubs (pub text)''')
            conn.commit()

    def create_nonce_table(self):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE nonces (nonce text)''')
            conn.commit()

    def write_contact(self, contact):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?)",
                (contact.name, contact.address, contact.phone, contact.email,
                contact.source, contact.key))
            conn.commit()

    def get_contacts(self, source):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            raw_contacts = cursor.execute(
                'SELECT name, address, phone, email, source, key from contacts WHERE source=?',
                (source,)).fetchall()
            contacts = []
            for contact in raw_contacts:
                c = Contact(*contact)
                contacts.append(c)
        return contacts

    def clear_db(self):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE from contacts')

    def has_pub(self, pub):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            if cursor.execute('SELECT pub from pubs where pub=?', 
                    (pub,)).fetchone() is None:
                return False
            else:
                return True

    def register_pub(self, pub):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO pubs VALUES (?)", (pub,))
            conn.commit()

    def use_nonce(self, nonce):
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            if cursor.execute('SELECT nonce from nonces where nonce=?', 
                    (nonce,)).fetchone() is None:
                cursor.execute('INSERT into nonces VALUES (?)', (nonce,))
            else:
                raise AuthorizationError('Nonce re-use')
            conn.commit()

class MissingParameterError(Exception):
    """
    http://flask.pocoo.org/docs/1.0/patterns/apierrors/
    """
    
    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

class AuthorizationError(Exception):
    """
    http://flask.pocoo.org/docs/1.0/patterns/apierrors/
    """
    
    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

app = Flask(__name__)
database = Database()


def authorized(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if 'Pub' not in request.headers:
            raise MissingParameterError('Missing authorization parameter: '
                'ECDSA pub')
        if 'Nonce' not in request.headers:
            raise MissingParameterError('Missing authorization parameter: '
                'Nonce')
        if 'Signature' not in request.headers:
            raise MissingParameterError('Missing authorization parameter: '
                'Signature')

        pub = b64decode(request.headers['Pub'].encode())
        nonce = request.headers['Nonce'].encode()
        signature = b64decode(request.headers['Signature'].encode())

        if not database.has_pub(pub):
            raise AuthorizationError('Pub is unregistered')
        database.use_nonce(nonce) # throws exception on re-use

        vk = VerifyingKey.from_string(pub, curve=CURVE)
        vk.verify(signature, nonce)

        return fn(pub=pub)
    return wrapper

@app.route('/add_contact', methods=['POST'])
@authorized
def add_contact(pub=None):
    name = get_json_value('name')
    address = get_json_value('address')
    phone = get_json_value('phone')
    email = get_json_value('email')
    source = get_json_value('source')
    key = get_json_value('key')
    try:
        database.write_contact(Contact(name, address, phone, email, source, key))
    except sqlite3.ProgrammingError:
        return jsonify(success=False)
    return jsonify(success=True)

@app.route('/list_contacts', methods=['GET'])
@authorized
def list_contacts(pub=None):
    source = get_param('source')
    contacts = database.get_contacts(source)
    return jsonify([contact.json() for contact in contacts])

@app.route('/clear_db', methods=['GET'])
@authorized
def clear_db(pub=None):
    database.clear_db()
    return 'OK'

@app.route('/register', methods=['POST'])
def register_pub():
    pub = b64decode(get_param('pub'))
    if database.has_pub(pub):
        return 'OK'
    database.register_pub(pub)
    # perhaps some error handling required???
    return 'OK'



def get_json_value(key):
    try: 
        return request.get_json()[key]
    except KeyError:
        raise MissingParameterError('Missing parameter: %s' % key,
            payload={'param' : key})

def get_param(p):
    try:
        return request.args.get(p)
    except KeyError:
        raise MissingParameterError('Missing parameter: %s' % p,
            payload={'param' : key})