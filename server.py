from flask import Flask, jsonify, request
from contact import Contact

import sqlite3

class Database(object):

    def __init__(self, path='contacts.db'):
        self.path = path
        self.conn = sqlite3.connect('contacts.db')

    def create_contacts_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''CREATE TABLE contacts
                            (name text, address text, phone text, email text, source text, key text)''')
        self.conn.commit()

    def write_contact(self, contact):
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO contacts VALUES (?,?,?,?,?,?)", 
            (contact.name, contact.address, contact.phone, contact.email,
            contact.source, contact.key))
        self.conn.commit()        

    def get_contacts(self, source):
        cursor = self.conn.cursor()
        print(source)
        raw_contacts = cursor.execute(
            'SELECT name, address, phone, email, source, key from contacts WHERE source=?', 
            (source,)).fetchall()
        contacts = []
        for contact in raw_contacts:
            c = Contact(*contact)
            contacts.append(c)
        return contacts

class MissingParameterError(Exception):
    
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

@app.route('/add_contact', methods=['POST'])
def add_contact():
    name = get_json_value('name')
    address = get_json_value('address')
    phone = get_json_value('phone')
    email = get_json_value('email')
    source = get_json_value('source')
    key = get_json_value('key')
    database.write_contact(Contact(name, address, phone, email, source, key))
    return jsonify(success=True)

@app.route('/list_contacts', methods=['GET'])
def list_contacts():
    source = get_param('source')
    contacts = database.get_contacts(source)
    return jsonify([contact.json() for contact in contacts])

def get_json_value(key):
    try: 
        return request.get_json()[key]
    except KeyError:
        raise MissingParameterError('Missing parameter: %s' % key)

def get_param(p):
    try:
        return request.args.get(p)
    except KeyError:
        raise MissingParameterError('Missing parameter: %s' % p)