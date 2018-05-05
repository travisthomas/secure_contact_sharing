#!/usr/bin/env python

import requests
from contact import Contact
from ecdsa import SigningKey, NIST256p, VerifyingKey
import os
from base64 import b64encode, b64decode

CURVE=NIST256p

class SecureShareClient(object):

    def __init__(self, name, home=None, server_url='http://127.0.0.1:5000'):
        if home is None:
            home = os.path.join(os.environ['HOME'], '.secure_contact_sharing')
        if not os.path.exists(home):
            os.mkdir(home)

        sk_path = os.path.join(home, 'ecdsa.priv')
        
        if os.path.exists(sk_path):
            self.sk = SigningKey.from_string(open(sk_path, 'rb').read(), 
                curve=CURVE)
            needs_register = False
        else:
            self.sk = SigningKey.generate(curve=CURVE)
            with open(sk_path, 'wb') as f:
                f.write(self.sk.to_string())
            needs_register = True
        self.url = { 
            'add_contact' : '/'.join([server_url, 'add_contact']),
            'list_contacts' : '/'.join([server_url, 'list_contacts']),
            'clear_db' : '/'.join([server_url, 'clear_db']),
            'register' : '/'.join([server_url, 'register'])
        }
        
        self.name = name
        self.vk = self.sk.get_verifying_key()
        if needs_register: self.register()


    def register(self):
        r = requests.post(self.url['register'], params={
            'pub' : b64encode(self.vk.to_string()).decode(),
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

class ECDSAAuth(requests.auth.AuthBase):
    
    def __init__(self, vk, sk):
        self.vk = vk
        self.sk = sk
        super(ECDSAAuth, self)
    
    def __call__(self, r):
        vks = self.vk.to_string()
        nonce = b64encode(os.urandom(16))
        signature = self.sk.sign(nonce)
        auth = {
            'Pub' : b64encode(vks).decode(),
            'Nonce' : nonce.decode(),
            'Signature' : b64encode(signature).decode()
        }
        r.headers.update(auth)
        return r