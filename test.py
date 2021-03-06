#!/usr/bin/env python3

import requests
import unittest
from contact import Contact
from sys import exit
from client import SecureShareClient
import os

tozny_address = '519 SW 3rd Ave suite 800, Portland, OR 97204'
tozny_phone = '(844) 628-2872'
source = 'ToznyInterview'

c = {}
c['Isaac'] = {
    'address' : tozny_address,
    'phone' : tozny_phone,
    'email' : 'isaac@tozny.com'
}
c['Kaila'] = {
    'address' : tozny_address,
    'phone' : tozny_phone,
    'email' : 'kaila@tozny.com'
}
c['Eric'] = {
    'address' : tozny_address,
    'phone' : tozny_phone,
    'email' : 'eric@tozny.com'
}
c['Justin'] = {
    'address' : tozny_address,
    'phone' : tozny_phone,
    'email' : 'justin@tozny.com'
}


class BasicTest(unittest.TestCase):
    
    secure_share_client = SecureShareClient('TestClient', 
            server_url='http://127.0.0.1:5000')
    
    def test_can_list(self):
        self.secure_share_client.list_contacts(source)

    def test_can_post(self):
        name = list(c.keys())[0]
        contact = c[name]
        self.secure_share_client.post_contact(name, contact['address'],
            contact['phone'], contact['email'], source)

    def test_post_contact_is_in_list(self):
        source = self.id()
        name = list(c.keys())[1]
        contact = c[name]
        self.secure_share_client.post_contact(name, contact['address'],
            contact['phone'], contact['email'], source)
        contacts = self.secure_share_client.list_contacts(source)
        new_contact = contacts[0] # should only be one
        assert new_contact.name == name
        assert new_contact.address == contact['address'] 
        assert new_contact.phone == contact['phone']
        assert new_contact.email == contact['email']
        assert new_contact.source == source

    def test_can_clear_db(self):
        for name in c:
            self.secure_share_client.post_contact(name, c[name]['address'], 
                c[name]['phone'], c[name]['email'], source)

        num_contacts = len(self.secure_share_client.list_contacts(source))
        self.secure_share_client.clear_db()
        self.secure_share_client.register()
        new_num_contacts = len(self.secure_share_client.list_contacts(source))
        assert num_contacts > 3
        assert new_num_contacts == 0

    def test_add_key_metadata(self):
        self.secure_share_client.post_contact('Travis', '444 Main St.',
            '360-888-5555', 'travisistall@gmail.com', self.id())
        contact = self.secure_share_client.list_contacts(source=self.id())[0]
        dek = contact._key
        self.secure_share_client.add_key_metadata(dek, 'owner', 'Telzey')
        self.secure_share_client.add_key_metadata(dek, 'user', 'Trigger')
        self.secure_share_client.add_key_metadata(dek, 'user', 'Danestar')

    def test_get_key_metadata(self):
        self.secure_share_client.post_contact('Cass', '555 Main St.',
            '360-888-7777', 'cass@gmail.com', self.id())
        contact = self.secure_share_client.list_contacts(source=self.id())[0]
        dek = contact._key
        self.secure_share_client.add_key_metadata(dek, 'owner', 'Telzey')
        self.secure_share_client.add_key_metadata(dek, 'user', 'Trigger')
        metadata = self.secure_share_client.get_key_metadata(dek)
        assert 'owner' in metadata
        assert 'user' in metadata
        assert 'Telzey' in metadata['owner']
        assert 'Trigger' in metadata['user']

    def test_remove_key_metadata(self):
        self.secure_share_client.post_contact('Vanessa', '66 Main St.',
            '360-888-6666', 'vanessa@gmail.com', self.id())
        contact = self.secure_share_client.list_contacts(source=self.id())[0]
        dek = contact._key
        self.secure_share_client.add_key_metadata(dek, 'owner', 'Telzey')
        self.secure_share_client.add_key_metadata(dek, 'user', 'Trigger')
        self.secure_share_client.add_key_metadata(dek, 'user', 'Danestar')
        metadata = self.secure_share_client.get_key_metadata(dek)
        assert 'owner' in metadata
        assert 'user' in metadata
        assert 'Telzey' in metadata['owner']
        assert 'Trigger' in metadata['user']
        self.secure_share_client.remove_key_metadata(dek, 'user', 'Trigger')
        metadata = self.secure_share_client.get_key_metadata(dek)
        assert 'user' in metadata
        assert metadata['user'] == ['Danestar',]
        self.secure_share_client.remove_key_metadata(dek, 'owner')
        metadata = self.secure_share_client.get_key_metadata(dek)
        assert 'owner' not in metadata
        self.secure_share_client.remove_key_metadata(dek)
        metadata = self.secure_share_client.get_key_metadata(dek)
        assert 'user' not in metadata
        assert 'name' not in metadata
