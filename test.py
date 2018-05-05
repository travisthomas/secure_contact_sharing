#!/usr/bin/env python3

import requests
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

secure_share_client = SecureShareClient('TestClient', 
    server_url='http://127.0.0.1:5000')


for name in c:
    secure_share_client.post_contact(name, c[name]['address'], 
        c[name]['phone'], c[name]['email'], source)

contacts = secure_share_client.list_contacts(source)
for contact in contacts:
    print('%s:\n%s\n%s\n%s\n' % (contact.name, contact.address, contact.phone,
        contact.email))

secure_share_client.clear_db()
