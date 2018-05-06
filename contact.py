#!/usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import binascii

class Contact(object):

    def __init__(self, name, address, phone, email, source, key=None):
        self.name = name
        self.address = address
        self.phone = phone
        self.email = email
        self.source = source
        self.encryptable_fields = [
            'name', 'address', 'phone', 'email'
        ]
        if key is not None:
            self.key = key

    def __str__(self):
        return 'Contact : %s' % self.name

    def set_key(self, binary_key):
        self.key = base64.b64encode(binary_key).decode()

    def get_key(self):
        return base64.b64decode(self.key.encode())

    def write(self, database):
        database.write_contact(self)

    def encrypt(self):
        if hasattr(self, 'key'):
            raise AlreadyEncryptedError()
        elif hasattr(self, '_key'):
            self.key = self._key
            delattr(self, '_key')
        else:
            context = ContactsContext()
            self.set_key(context.new_key())
        for f in self.encryptable_fields:
            field = getattr(self, f)
            iv = context.new_iv()
            cipher = context.new_cipher(self.get_key(), iv)
            encryptor = cipher.encryptor()
            padded_field = context.pad(field)
            binary_field = encryptor.update(padded_field) + encryptor.finalize()
            setattr(self, f, base64.b64encode(iv + binary_field).decode())

    def decrypt(self):
        try:
            self.key
        except AttributeError:
            raise NotEncryptedError() from None
        context = ContactsContext()
        for f in self.encryptable_fields:
            field = getattr(self, f).encode()
            try:
                binary_value = base64.b64decode(field)
            except binascii.Error:
                print('%s is invalid base64: %s' % (f, field))
            iv = binary_value[:16]
            value = binary_value[16:]
            cipher = context.new_cipher(self.get_key(), iv)
            decryptor = cipher.decryptor()
            setattr(self, f, context.unpad(decryptor.update(value) + decryptor.finalize()).decode())
        setattr(self, '_key', self.key)
        delattr(self, 'key')

    def json(self):
        value = {
            'name' : self.name,
            'address' : self.address,
            'phone' : self.phone,
            'email' : self.email,
            'source' : self.source
        }
        try: 
            value['key'] = self.key
        except AttributeError:
            pass
        return value

class ContactsContext(object):

    def __init__(self):
        self.backend = default_backend()

    def new_key(self):
        return os.urandom(32)

    def new_iv(self):
        return os.urandom(16)

    def new_cipher(self, key, iv):
        return Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)

    def pad(self, value):
        padder = padding.PKCS7(128).padder()
        try:
            padded_value = padder.update(value) + padder.finalize()
        except TypeError:
            value = value.encode()
            padded_value = padder.update(value) + padder.finalize()
        return padded_value

    def unpad(self, value):
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(value) + unpadder.finalize()

class AlreadyEncryptedError(BaseException): pass
class NotEncryptedError(BaseException): pass