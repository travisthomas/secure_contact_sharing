#!/usr/bin/env python3

import requests
from contact import Contact
from sys import exit

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

contacts = []
for name in c:
    print(name)
    contact = Contact(name, c[name]['address'], c[name]['phone'], c[name]['email'], source)
    contact.encrypt()
    contact.decrypt()
    contacts.append(contact)

for contact in contacts:
    contact.encrypt()
    r = requests.post('http://127.0.0.1:5000/add_contact', json=contact.json())
    print(r.json())

r = requests.get('http://127.0.0.1:5000/list_contacts', params={'source' : source })
try:
    json = r.json()
except json.decoder.JSONDecodeError:
    print('Failed to list contacts!')
    exit(1)
print(json)

returned_contacts = []

for c in json:
    returned_contacts.append(Contact(name=c['name'], address=c['address'], 
        phone=c['phone'], email=c['email'], source=c['source'], key=c['key']))

for c in returned_contacts:
    c.decrypt()
    print(c.json())

print(returned_contacts)