import lxml.etree as ET
from OpenSSL import crypto
import hashlib
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os
from Crypto.PublicKey import RSA


def convert_cer_to_pem(cer_path):
    with open(cer_path, 'rb') as f:
        cert_data = f.read()
        cert = x509.load_der_x509_certificate(cert_data)
        pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    with open("F_cer.pem", "w") as f:
        f.write(pem_cert.decode())
    return pem_cert.decode()


def convert_fiel_cer_to_pem(cer_path):
    with open(cer_path, 'rb') as f:
        cert_data = f.read()
        cert = x509.load_der_x509_certificate(cert_data)
        pem_fiel_cert = cert.public_bytes(serialization.Encoding.PEM)
    with open("F_fiel_cer.pem", "w") as f:
        f.write(pem_fiel_cert.decode())
    return pem_fiel_cert.decode()


def convert_key_to_pem(key_path):
    clave = open(key_path, "rb").read()
    key = RSA.import_key(clave, passphrase="12345678a")
    pv_key_string = key.exportKey(pkcs=8)
    with open("F_key.pem", "w") as f:
        f.write(pv_key_string.decode())
    return pv_key_string.decode()


def convert_fiel_key_to_pem(key_path):
    clave = open(key_path, "rb").read()
    key = RSA.import_key(clave, passphrase="12345678a")
    pv_fiel_key_string = key.exportKey(pkcs=8)
    with open("F_fiel_key.pem", "w") as f:
        f.write(pv_fiel_key_string.decode())
    return pv_fiel_key_string.decode()


if __name__ == '__main__':
    cer_file = 'cert.cer'
    key_file = 'key.key'
    cer_fiel_file = 'fiel_cer.cer'
    key_fiel_file = 'fiel_key.key'

    if os.path.exists(cer_file):
        pem_cert = convert_cer_to_pem(cer_file)

    if os.path.exists(key_file):
        pem_key = convert_key_to_pem(key_file)

    if os.path.exists(key_fiel_file):
        pem_fiel_key = convert_fiel_key_to_pem(key_fiel_file)

    if os.path.exists(cer_fiel_file):
        pem_fiel_cert = convert_fiel_cer_to_pem(cer_fiel_file)
