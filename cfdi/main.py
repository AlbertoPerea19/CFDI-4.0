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
    return pem_cert.decode()

def convert_key_to_pem(key_path):  
    clave = open(key_path, "rb").read()
    key = RSA.import_key(clave, passphrase="12345678a")
    pv_key_string = key.exportKey(pkcs=8)
    return pv_key_string.decode()

def generateCadenaOriginal(cfdi_file, cadenaOriginal_file):
    # Cargar el archivo XML del CFDI
    with open(cfdi_file, 'rb') as f:
        xml_data = f.read()
    root = ET.fromstring(xml_data)

    # Cargar la hoja de estilos XSLT para generar la cadena original
    with open(cadenaOriginal_file, 'rb') as f:
        xslt_data = f.read()
    xslt_root = ET.fromstring(xslt_data)
    transform = ET.XSLT(xslt_root)

    return root,str(transform(root))

def generateSign(pem_cert,pem_key, cadena_original):
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, pem_key)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)

    # Generar el hash SHA-256
    hash_sha256 = hashlib.sha256(cadena_original.encode('utf-8')).digest()
    print(hash_sha256,"\n\n")
    # Firmar el hash con el certificado digital
    signature = crypto.sign(key, hash_sha256, 'sha256')

    return base64.b64encode(signature).decode(), cert

if __name__ == '__main__':
    cer_file = 'cert.cer'
    key_file = 'key.key'
    cfdi_file = 'cfdi.xml'
    cadenaOriginal_file = 'cadenaoriginal_4_0.xslt'

    if os.path.exists(cer_file):
        pem_cert = convert_cer_to_pem(cer_file)

    if os.path.exists(key_file):
        pem_key = convert_key_to_pem(key_file)

    root, cadena_original = generateCadenaOriginal(cfdi_file, cadenaOriginal_file)
    firma_base64, cert=generateSign(pem_cert,pem_key, cadena_original)

    # Agregar el sello digital al CFDI
    root.set('Sello', firma_base64)
    # root.set('Certificado', cert)

    # Guardar el archivo XML del CFDI sellado
    with open('cfdi_sellado.xml', 'wb') as f:
        f.write(ET.tostring(root, encoding='UTF-8', xml_declaration=True))
