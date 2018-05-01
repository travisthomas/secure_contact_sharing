#!/usr/bin/env python

import requests
from contact import Contact

class SecureShareClient(object):

    ecdsa_key = None

    def __init__(self, ecdsa_key_path, server_url='http://127.0.0.1:5000'):
        self.ecdsa_key = ecdsa_key_path
        self.server = server_url

    def _add_contact_url(self):
        return '/'.join([self.server, 'add_contact'])

    def _list_contacts_url(self):
        return '/'.join([self.server, 'list_contacts'])

    def post_contact(self, name, address, phone, email, source):
        c = Contact(name, address, phone, email, source)
        c.encrypt()
        url = self._add_contact_url()
        r = requests.post(url, json=c.json())
        r.raise_for_status()

    def list_contacts(self, source):
        r = requests.get(self._list_contacts_url(), params={'source' : source})
        r.raise_for_status()
        json = r.json()
        returned_contacts = [Contact(c['name'], c['address'], c['phone'],
            c['email'], source, c['key']) for c in json]
        for c in returned_contacts:
            print(c.name)
            c.decrypt()
        return returned_contacts