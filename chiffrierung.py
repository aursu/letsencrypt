#!/usr/bin/python
# -*- coding: utf-8 -*-

from utils import BaseUtils
import OpenSSL
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes
import os.path
import json, hashlib, base64

DEFAULT_KEY_SIZE = 2048
# https://tools.ietf.org/html/rfc3339#section-5.6
SSL_DATETIME_FORMAT = "%Y-%m-%dT00:00:00Z"

class SSLObject(BaseUtils):

    cert = None
    PKey = None
    CSR = None

    def __init__(self):
        super(SSLObject, self).__init__()

    def loadCertificateRequest(self, objtext):
        rawdata = self.getBytes(objtext)
        self.CSR = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, rawdata)

    def loadPrivateKey(self, objtext):
        rawdata = self.getBytes(objtext)
        self.PKey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_ASN1, rawdata)

    def loadCertificate(self, objtext):
        rawdata = self.getBytes(objtext)
        try:
            self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, rawdata)
        except OpenSSL.crypto.Error:
            self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, rawdata)

    def getNames(self):
        names = []
        extensions = []
        # if object exists and is Certificate or Certificate Signing Request
        if isinstance(self.cert, OpenSSL.crypto.X509) \
            or isinstance(self.cert, OpenSSL.crypto.X509Req):
            # get its subject
            subject = self.cert.get_subject()
            if subject.commonName:
                if subject.commonName:
                    names = [ str(subject.commonName) ]
            # get its extensions
            extensions = self.cert.get_extensions()
        # look for subjectAltName X509 extension and DNS names inside it
        altnames = []
        for e in extensions:
            if str(e.get_short_name()) == "subjectAltName":
                parts = [ p.strip() for p in str(e).split(",") ]
                altnames =  [ n for a in parts if len(a) > 3 and a[:3] == "DNS" for n in a.split(":") if n != "DNS" ]

        return names + altnames

    def generateKey(self, bits = DEFAULT_KEY_SIZE, ktyp = OpenSSL.crypto.TYPE_RSA):
        self.PKey = OpenSSL.crypto.PKey()
        self.PKey.generate_key(ktyp, bits)
        return self.getKey()

    def getKey(self, form = "DER"):
        if isinstance(self.PKey, OpenSSL.crypto.PKey):
            if form == "PEM":
                filetype = OpenSSL.crypto.FILETYPE_PEM
            else:
                filetype = OpenSSL.crypto.FILETYPE_ASN1
            return OpenSSL.crypto.dump_privatekey(filetype, self.PKey)
        return None

    # /C=DE/ST=Hessen/L=Frankfurt am Main/O=Company Inc/OU=Web Department/CN=rest.api.test.gface.de
    def generateCSR(self, subj, sans = [] ):

        subjHash = dict([ tuple(i) for i in [ p.split("=") for p in  subj.split('/') ] if len(i) == 2 ])

        self.CSR = OpenSSL.crypto.X509Req()

        if "C" in subjHash:
            self.CSR.get_subject().countryName = subjHash["C"]
        if "ST" in subjHash:
            self.CSR.get_subject().stateOrProvinceName = subjHash["ST"]
        if "L" in subjHash:
            self.CSR.get_subject().localityName = subjHash["L"]
        if "O" in subjHash:
            self.CSR.get_subject().organizationName = subjHash["O"]
        if "OU" in subjHash:
            self.CSR.get_subject().organizationalUnitName = subjHash["OU"]
        self.CSR.get_subject().CN = subjHash["CN"]

        x509_extensions = [
            OpenSSL.crypto.X509Extension("keyUsage", True, "digitalSignature, keyEncipherment"),
            OpenSSL.crypto.X509Extension("basicConstraints", True, "CA:FALSE")
        ]

        if isinstance(sans, list) and sans:
            subjectAltName = ", ".join(["DNS:" + d for d in sans])
            x509_extensions += [
                OpenSSL.crypto.X509Extension("subjectAltName", False, subjectAltName)
            ]

        self.CSR.add_extensions(x509_extensions)

        if not isinstance(self.PKey, OpenSSL.crypto.PKey):
            self.generateKey()

        self.CSR.set_pubkey(self.PKey)
        self.CSR.sign(self.PKey, "sha256")

        return self.getCSR()

    def getCSR(self, form = "DER"):
        if isinstance(self.CSR, OpenSSL.crypto.X509Req):
            if form == "PEM":
                filetype = OpenSSL.crypto.FILETYPE_PEM
            else:
                filetype = OpenSSL.crypto.FILETYPE_ASN1
            return OpenSSL.crypto.dump_certificate_request(filetype, self.CSR)
        return None

    def getCert(self, form = "DER"):
        if isinstance(self.cert, OpenSSL.crypto.X509):
            if form == "PEM":
                filetype = OpenSSL.crypto.FILETYPE_PEM
            else:
                filetype = OpenSSL.crypto.FILETYPE_ASN1
            return OpenSSL.crypto.dump_certificate(filetype, self.cert)
        return None

    def getCSRSubject(self):
        if isinstance(self.CSR, OpenSSL.crypto.X509Req):
            name = self.CSR.get_subject()
            s = name.get_components()
            return "/" + "/".join([ "=".join(c) for c in s ])
        return None
# http://pythonhosted.org/pycrypto/Crypto.Signature.PKCS1_v1_5-module.html
# http://pythonhosted.org/pycrypto/Crypto.PublicKey.RSA-module.html
class RSAKey(BaseUtils):

    # http://pythonhosted.org/pycrypto/Crypto.PublicKey.RSA._RSAobj-class.html
    # object of Class _RSAobj
    priv = None
    pub = None

    def __init__(self):
        super(RSAKey, self).__init__()

    def __loadKey(self, fname):
        key = None
        if os.path.isfile(fname):
            f = self.openfile(fname)
            try:
                key = RSA.importKey(f.read())
            except ValueError:
                key = None
            f.close()
        return key

    def __saveKey(self, key, fname, form ):
        if form not in ( "PEM", "DER" ):
            form = "DER"
        if isinstance(key, RSA._RSAobj):
            kdata = key.exportKey(form)
            f = self.openfile(fname, "w")
            f.write(kdata)
            f.close()
            return kdata
        return None

    def loadPrivate(self, key):
        if isinstance(key, basestring) and key:
            rawdata = self.getBytes(key)
            key = RSA.importKey(rawdata)
        if isinstance(key, RSA._RSAobj) and key.has_private():
            self.priv = key
            self.pub = key.publickey()
            return self.priv
        return None

    def loadPrivateFile(self, fname):
        key = self.__loadKey(fname)
        return self.loadPrivate(key)

    def loadPublic(self, key):
        if isinstance(key, basestring) and key:
            rawdata = self.getBytes(key)
            key = RSA.importKey(rawdata)
        if isinstance(key, RSA._RSAobj):
            if not key.has_private():
                self.pub = key
                return self.pub
        return None

    def loadPublicFile(self, fname):
        key = self.__loadKey(fname)
        return self.loadPublic(key)

    def savePrivateFile(self, fname, form = "DER"):
        return self.__saveKey(self.priv, fname, form)

    def exportPrivate(self, form = "DER"):
        if isinstance(self.priv, RSA._RSAobj):
            return self.priv.exportKey(form)
        return None

    def savePublicFile(self, fname, form = "DER"):
        return self.__saveKey(self.pub, fname, form)

    def exportPublic(self, form = "DER"):
        if isinstance(self.pub, RSA._RSAobj):
            return self.pub.exportKey(form)
        return None

    def generate(self, bits = DEFAULT_KEY_SIZE):
        self.priv = RSA.generate(bits)
        self.pub = self.priv.publickey()
        return self.priv

    # The "n" (modulus) parameter contains the modulus value for the RSA public
    # key
    def modulus(self):
        if isinstance(self.pub, RSA._RSAobj):
            return long_to_bytes(self.pub.n)
        return None

    # The "e" (exponent) parameter contains the exponent value for the RSA
    # public key
    def exponent(self):
        if isinstance(self.pub, RSA._RSAobj):
            return long_to_bytes(self.pub.e)
        return None

    def size(self):
        if isinstance(self.pub, RSA._RSAobj):
            return self.pub.size() + 1
        return None

class RS256Signer(RSAKey):

    def __init__(self):
        super(RS256Signer, self).__init__()

    # RS256 | RSASSA-PKCS1-v1_5 using SHA-256
    # https://tools.ietf.org/html/rfc7518#section-3.3
    def sign(self, message):
        if isinstance(self.priv, RSA._RSAobj):
            h = SHA256.new(message)
            s = PKCS1_v1_5.new(self.priv)
            return s.sign(h)
        return None

    def JWK(self):
        return { "kty": "RSA", "n": self.modulus(), "e": self.exponent() }

    # https://tools.ietf.org/html/rfc7638#section-3
    def JWKThumbprint(self):
        jwk = json.dumps(self.JWK(), indent = None, separators = (',', ':'), sort_keys = True)
        return hashlib.sha256(jwk).digest()

    # * The JWS Protected Header MUST include the following fields:
    #   - "alg" (Algorithm)
    #   - "jwk" (JSON Web Key, for all requests not signed using an existing
    #     account, e.g. newAccount)
    # * The JWS MUST NOT have a Message Authentication Code (MAC)-based
    #  algorithm in its "alg" field
    #
    # https://letsencrypt.github.io/acme-spec/#terminology
    def joseHeader(self):
        return { "alg": "RS256", "jwk": self.JWK() }

    # Base64urlUInt-encoded
    def exponent(self):
        e = super(RS256Signer, self).exponent()
        if e:
            return self.base64urlencode(e)
        return None

    # Base64urlUInt-encoded
    def modulus(self):
        n = super(RS256Signer, self).modulus()
        if n:
            return self.base64urlencode(n)
        return None