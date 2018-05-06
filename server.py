from flask import Flask, jsonify, request
from contact import Contact
from ecdsa import SigningKey, VerifyingKey, NIST256p
from functools import wraps
from base64 import b64encode, b64decode
from os.path import exists
import logging
import sqlite3

logger = logging.getLogger('SecureContactSharing')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

CURVE=NIST256p

class Database(object):

    def __init__(self, path='contacts.db'):
        logger.debug('Initializing database')
        self.path = path
        if not exists(self.path):
            logger.debug('Creating database')
            self.create_contacts_table()
            self.create_keys_table()
            self.create_nonce_table()

    def create_contacts_table(self):
        logger.debug('Creating contacts table')
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE contacts
                                (name text, address text, phone text, email text, source text, key text)''')
            conn.commit()

    def create_keys_table(self):
        logger.debug('Creating keys table')
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE keys (key text, md_name text, md_value text)''')
            conn.commit()

    def create_nonce_table(self):
        logger.debug('Creating nonce table')
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE nonces (nonce text)''')
            conn.commit()

    def write_contact(self, contact):
        logger.debug('Writing contact for source: %s' % contact.source)
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?)",
                (contact.name, contact.address, contact.phone, contact.email,
                contact.source, contact.key))
            conn.commit()

    def get_contacts(self, source):
        logger.debug('Getting contacts for source: %s' % source)
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            raw_contacts = cursor.execute(
                'SELECT name, address, phone, email, source, key from contacts WHERE source=?',
                (source,)).fetchall()
            contacts = []
            for contact in raw_contacts:
                c = Contact(*contact)
                contacts.append(c)
        logger.debug(contacts)
        return contacts

    def clear_db(self):
        logger.debug('Clearing tables in database: contacts, keys, nonces')
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE from contacts')
            cursor.execute('DELETE from keys')
            cursor.execute('DELETE from nonces')

    def has_key(self, key):
        logger.debug('has_key: %s' % key)
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            if cursor.execute('SELECT key from keys where key=?', 
                    (key,)).fetchone() is None:
                return False
            else:
                return True

    def register_key(self, key, name):
        self.add_key_metadata(key, 'name', name)

    def add_key_metadata(self, key, md_name, md_value):
        logger.debug('insert_key: %s: {"%s" : "%s"}' % (key, md_name, md_value))
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO keys (key, md_name, md_value) VALUES "
                "(?, ?, ?)", (key, md_name, md_value))
            conn.commit()

    def get_key_metadata(self, key):
        logger.debug('get_key_metadata: %s' % key)
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            cursor = cursor.execute('SELECT md_name, md_value from keys '
                'where key=?', (key,))
            metadata = cursor.fetchall()
            return_metadata = {}
            for name, value in metadata:
                if name in return_metadata.keys():
                    return_metadata[name] += (value,)
                else:
                    return_metadata[name] = (value,)
            logger.debug(return_metadata)
        return return_metadata

    def remove_key_metadata(self, key, md_name=None, md_value=None):
        logger.debug('remove_key_metadata: %s' % key)
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            query = 'DELETE from keys where key=?'
            params = (key,)
            if md_name:
                query = ' AND '.join([query, 'md_name=?'])
                params += (md_name,)
            if md_value:
                query = ' AND '.join([query, 'md_value=?'])
                params += (md_value,)
            logger.debug(query)
            logger.debug(params)
            data = cursor.execute(query, params)
            logger.debug(data)

    def use_nonce(self, nonce):
        logger.debug('use_nonce: %s' % nonce)
        with sqlite3.connect(self.path) as conn:
            cursor = conn.cursor()
            if cursor.execute('SELECT nonce from nonces where nonce=?', 
                    (nonce,)).fetchone() is None:
                cursor.execute('INSERT into nonces VALUES (?)', (nonce,))
            else:
                raise AuthorizationError('Nonce has been used before')
            conn.commit()

class FlaskError(Exception):
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
        
class MissingParameterError(FlaskError): pass
class AuthorizationError(FlaskError): pass

app = Flask(__name__)
database = Database()


def authorized(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        logger.debug('Authorizing request')
        if 'Pub' not in request.headers:
            raise MissingParameterError('Missing authorization parameter: '
                'ECDSA public key')
        if 'Nonce' not in request.headers:
            raise MissingParameterError('Missing authorization parameter: '
                'Nonce')
        if 'Signature' not in request.headers:
            raise MissingParameterError('Missing authorization parameter: '
                'Signature')

        key = b64decode(request.headers['Pub'].encode())
        nonce = request.headers['Nonce'].encode()
        signature = b64decode(request.headers['Signature'].encode())

        if not database.has_key(key):
            raise AuthorizationError('ECDSA public key is unregistered')
        database.use_nonce(nonce) # throws exception on re-use

        vk = VerifyingKey.from_string(key, curve=CURVE)
        vk.verify(signature, nonce)

        return fn(pub=key)
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
    return jsonify(success=True)

@app.route('/register', methods=['POST'])
def register_key():
    pub = b64decode(get_param('pub'))
    name = get_param('name')
    if database.has_key(pub):
        return 'OK'
    database.register_key(pub, name)
    # perhaps some error handling required???
    return jsonify(success=True)

@app.route('/add_key_metadata', methods=['POST'])
@authorized
def add_key_metadata(pub=None):
    key = get_json_value('Key')
    md_name = get_json_value('Name')
    md_value = get_json_value('Value')
    database.add_key_metadata(key, md_name, md_value)
    return jsonify(success=True)

@app.route('/remove_key_metadata', methods=['POST'])
@authorized
def remove_key_metadata(pub=None):
    key = get_json_value('Key')
    try:
        md_name = get_json_value('Name')
    except MissingParameterError:
        md_name = None
    try:
        md_value = get_json_value('Value')
    except MissingParameterError:
        md_value = None
    database.remove_key_metadata(key, md_name, md_value)
    return jsonify(success=True)

@app.route('/get_key_metadata', methods=['POST'])
@authorized
def get_key_metadata(pub=None):
    key = get_json_value('Key')
    metadata = database.get_key_metadata(key)
    return jsonify(metadata)

def get_json_value(key):
    try: 
        return request.get_json()[key]
    except KeyError:
        raise MissingParameterError('Missing required JSON parameter: %s' % key,
            payload={'param' : key})

def get_param(p):
    try:
        return request.args.get(p)
    except KeyError:
        raise MissingParameterError('Missing required header parameter: %s' % p,
            payload={'param' : key})