#!/usr/bin/env python

import requests
from contact import Contact
from ecdsa import SigningKey, NIST256p, VerifyingKey
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

CURVE=NIST256p

class SecureShareClient(object):

    def __init__(self, name, home=None, server_url='http://127.0.0.1:5000'):
        if home is None:
            home = os.path.join(os.environ['HOME'], '.secure_contact_sharing')
        if not os.path.exists(home):
            os.mkdir(home)

        sign_key_path = os.path.join(home, 'ecdsa.priv')
        dec_key_path = os.path.join(home, 'rsa.priv')
        
        if (os.path.exists(sign_key_path)
                and not os.path.exists(dec_key_path)) or \
                (os.path.exists(dec_key_path)
                and not os.path.exists(sign_key_path)):
            raise Exception # TODO????
        if os.path.exists(sign_key_path) and os.path.exists(dec_key_path):
            self.sk = SigningKey.from_string(open(sign_key_path, 'rb').read(), 
                curve=CURVE)
            with open(dec_key_path, mode='rb') as privatefile:
                self.dk = serialization.load_pem_private_key(
                    privatefile.read(), password=None, backend=default_backend()
                )
            self.ek = self.dk.public_key()
            needs_register = False
        else:
            self.sk = SigningKey.generate(curve=CURVE)
            with open(sign_key_path, 'wb') as f:
                f.write(self.sk.to_string())
            self.dk = rsa.generate_private_key(public_exponent=65537,
                key_size=2048, backend=default_backend())
            self.ek = self.dk.public_key()
            with open(dec_key_path, 'wb') as f:
                f.write(self.dk.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            needs_register = True
        self.url = { 
            'add_contact' :         '/'.join([server_url, 'add_contact']),
            'list_contacts' :       '/'.join([server_url, 'list_contacts']),
            'clear_db' :            '/'.join([server_url, 'clear_db']),
            'register' :            '/'.join([server_url, 'register']),
            'add_key_metadata' :    '/'.join([server_url, 'add_key_metadata']),
            'get_key_metadata' :    '/'.join([server_url, 'get_key_metadata']),
            'remove_key_metadata' : '/'.join([server_url, 'remove_key_metadata'])
        }
        
        self.name = name
        self.vk = self.sk.get_verifying_key()
        if needs_register: self.register()


    def register(self):
        r = requests.post(self.url['register'], params={
            'ecdsa-pub' : b64encode(self.vk.to_string()).decode(),
            'rsa-pub' : self.ek.public_bytes(
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encoding=serialization.Encoding.PEM),
            'name' : self.name
        })
        r.raise_for_status()

    def post_contact(self, name, address, phone, email, source):
        c = Contact(name, address, phone, email, source)
        c.encrypt()
        r = requests.post(self.url['add_contact'], json=c.json(), 
            auth=ECDSAAuth(self.vk, self.sk))
        r.raise_for_status()

    def list_contacts(self, source):
        r = requests.get(self.url['list_contacts'], params={'source' : source},
            auth=ECDSAAuth(self.vk, self.sk))
        r.raise_for_status()
        json = r.json()
        returned_contacts = [Contact(c['name'], c['address'], c['phone'],
            c['email'], source, c['key']) for c in json]
        for c in returned_contacts:
            c.decrypt()
        return returned_contacts

    def clear_db(self):
        r = requests.get(self.url['clear_db'], auth=ECDSAAuth(self.vk, self.sk))
        r.raise_for_status()

    def add_key_metadata(self, key, md_name, md_value):
        data = {
            'Key' : key,
            'Name' : md_name,
            'Value' : md_value
        }
        r = requests.post(self.url['add_key_metadata'], json=data,
            auth=ECDSAAuth(self.vk, self.sk))
        r.raise_for_status()

    def get_key_metadata(self, key):
        data = {
            'Key' : key
        }
        r = requests.post(self.url['get_key_metadata'], json=data,
            auth=ECDSAAuth(self.vk, self.sk))
        r.raise_for_status()
        return r.json()

    def remove_key_metadata(self, key, md_name=None, md_value=None):
        data = {
            'Key' : key
        }
        if md_name is not None:
            data['Name'] = md_name
        if md_value is not None:
            data['Value'] = md_value
        r = requests.post(self.url['remove_key_metadata'], json=data,
            auth=ECDSAAuth(self.vk, self.sk))
        r.raise_for_status()

class ECDSAAuth(requests.auth.AuthBase):
    
    def __init__(self, vk, sk):
        self.vk = vk
        self.sk = sk
        super(ECDSAAuth, self)
    
    def __call__(self, r):
        vks = self.vk.to_string()
        nonce = b64encode(os.urandom(18))
        signature = self.sk.sign(nonce)
        auth = {
            'Pub' : b64encode(vks).decode(),
            'Nonce' : nonce.decode(),
            'Signature' : b64encode(signature).decode()
        }
        r.headers.update(auth)
        return r