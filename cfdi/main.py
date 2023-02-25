import lxml.etree as ET
from OpenSSL import crypto
import hashlib
import base64


# Cargar el archivo XML del CFDI
with open('ejemplo_cfdi_40.xml', 'rb') as f:
    xml_data = f.read()
root = ET.fromstring(xml_data)

# Cargar la hoja de estilos XSLT para generar la cadena original
with open('cadenaoriginal_4_0.xslt', 'rb') as f:
    xslt_data = f.read()
xslt_root = ET.fromstring(xslt_data)
transform = ET.XSLT(xslt_root)

# Aplicar la transformación y obtener la cadena original
cadena_original = str(transform(root))


with open('EKU9003173C9.key.pem', 'rb') as f:
    key_data = f.read()
key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)
with open('EKU9003173C9.cer.pem', 'rb') as f:
    cert_data = f.read()
cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

# Generar el hash SHA-256
hash_sha256 = hashlib.sha256(cadena_original.encode('utf-8')).digest()

# Firmar el hash con el certificado digital
signature = crypto.sign(key, hash_sha256, 'sha256')

# Convertir la firma en base64
firma_base64 = base64.b64encode(signature).decode()


# Agregar el sello digital al CFDI
root.set('Sello', firma_base64)

# Guardar el archivo XML del CFDI sellado
with open('cfdi_sellado.xml', 'wb') as f:
    f.write(ET.tostring(root, encoding='UTF-8', xml_declaration=True))
