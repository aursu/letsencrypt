#!/usr/bin/python
# -*- coding: utf-8 -*-

import os.path
import json
import hashlib
import time
from web import WebResource, WebResponse, WebInterface
from parsers import JSONParser
from utils import Utils, BaseUtils
from chiffrierung import RS256Signer, SSLObject, DEFAULT_KEY_SIZE, SSL_DATETIME_FORMAT
from config import DomainConfig
from log import LogInterface

# https://acme-v01.api.letsencrypt.org/
# https://tools.ietf.org/html/draft-ietf-acme-acme-01
class LetsEncryptACME(WebResource):
    def __init__(self):
        super(LetsEncryptACME, self).__init__("acme-v01.api.letsencrypt.org")
        self.secure(True)

# https://community.letsencrypt.org/t/acme-v2-production-environment-wildcards/55578
# https://tools.ietf.org/html/draft-ietf-acme-acme-10
class LetsEncryptACMEV2(WebResource):
    def __init__(self):
        super(LetsEncryptACMEV2, self).__init__("acme-v02.api.letsencrypt.org")
        self.secure(True)

# In order to help clients configure themselves with the right URIs for each
# ACME operation, ACME servers provide a directory object. This should be the
# root URL with which clients are configured. It is a JSON dictionary, whose
# keys are the "resource" values listed in Section 5.1, and whose values are the
# URIs used to accomplish the corresponding function.
# Clients access the directory by sending a GET request to the directory URI.
# https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-6.2
#
# https://acme-v01.api.letsencrypt.org/directory
class ACMEDirectory(LetsEncryptACME):
    def __init__(self):
        super(ACMEDirectory, self).__init__()
        self.setPath("directory")

class ACMEDirectoryV2(LetsEncryptACMEV2):
    def __init__(self):
        super(ACMEDirectoryV2, self).__init__()
        self.setPath("directory")

class ACMEObject(JSONParser):

    def __init__(self, data = None):
        super(ACMEObject, self).__init__()
        # reset is going next inside feed() method
        self.feed(data)

    def feed(self, data):
        self.reset()
        if isinstance(data, basestring) and data:
            self.fromstring(data)
            # propagate received data from parser into ACMEObject itself
            if self.jsonobj:
                for f in self.jsonobj:
                    self[f] = self.jsonobj[f]
                return self.jsonobj
        return None

    # returned by ACME dictionary object should be dictionary
    def valid(self):
        return isinstance(self.jsonobj, dict)

class LetsEncryptResource(ACMEObject, WebInterface, LogInterface):

    __name = None

    # url is predefined to None as non required during initialization
    def __init__(self, name, url = None):
        super(LetsEncryptResource, self).__init__()

        if isinstance(name, basestring) and name:
            self.__name = name

        # URL could be fetched by resource name from provided dictionary object
        if isinstance(url, Utils) or isinstance(url, dict):
            self.debug("resource name \"%s\" is in dictionary object (%s): %s" %
                    (self.__name, url.__class__.__name__, self.__name in url))
            if self.__name and self.__name in url:
                url = url[self.__name]
                # The "url" header parameter specifies the URL [RFC3986] to
                # which this JWS object is directed. The "url" header parameter
                # MUST be carried in the protected header of the JWS. The value
                # of the "url" header parameter MUST be a string representing
                # the URL.
                #
                # https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-6.3.1
                self["url"] = url

        if isinstance(url, basestring) and url:
            self.setURL(url)

    def getName(self):
        return self.__name

    # The "nonce" header parameter provides a unique value that enables the
    # verifier of a JWS to recognize when replay has occurred.  The "nonce"
    # header parameter MUST be carried in the protected header of the JWS.
    # The value of the "nonce" header parameter MUST be an octet string, encoded
    # according to the base64url encoding described in Section 2 of [RFC7515].
    # If the value of a "nonce" header parameter is not valid according to this
    # encoding, then the verifier MUST reject the JWS as malformed.
    # https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.5.2
    def setNonce(self, response):
        if isinstance(response, WebResponse) and "Replay-Nonce" in response:
            self["nonce"] = response["Replay-Nonce"]

    def send(self, data = None):
        self.request.setMethod("GET")
        # Because client requests in ACME carry JWS objects in the Flattened
        # JSON Serialization, they must have the "Content-Type" header field set
        # to "application/jose+json". If a request does not meet this
        # requirement, then the server MUST return a response with status code
        # 415 (Unsupported Media Type).
        if data:
            self.request["Content-Type"] = "application/jose+json"
        response = self.sendRequest(data)
        # if request was failed, status is not set
        if not isinstance(response, WebResponse):
            return None
        self.feed(response.getBody())
        self.setNonce(response)
        return response

    def info(self):
        self.request.setMethod("HEAD")
        response = self.sendRequest()
        # if request was failed, status is not set
        if not isinstance(response, WebResponse):
            return None
        self.setNonce(response)
        return response

    def payload(self):
        return None

# 7.1.1.  Directory
#
# In order to help clients configure themselves with the right URLs for each
# ACME operation, ACME servers provide a directory object.  This should be the
# only URL needed to configure clients.  It is a JSON object, whose field names
# are drawn from the following table and whose values are the corresponding URLs.
#                    +------------+--------------------+
#                    | Field      | URL in value       |
#                    +------------+--------------------+
#                    | newNonce   | New nonce          |
#                    | newAccount | New account        |
#                    | newOrder   | New order          |
#                    | newAuthz   | New authorization  |
#                    | revokeCert | Revoke certificate |
#                    | keyChange  | Key change         |
#                    +------------+--------------------+
# https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.1.1
class LetsEncryptDirectory(LetsEncryptResource):

    def __init__(self, ACMEClass = ACMEDirectoryV2):
        super(LetsEncryptDirectory, self).__init__("directory")
        self.resource = ACMEClass()

    def send(self, data = None):
        super(LetsEncryptDirectory, self).send()
        return self.object()

# To get a fresh nonce, the client sends a HEAD request to the new-nonce
# resource on the server. The server's response MUST include a Replay-Nonce
# header field containing a fresh nonce, and SHOULD have status code 200 (OK).
# The server SHOULD also respond to GET requests for this resource, returning an
# empty body (while still providing a Replay-Nonce header) with a 204
# (No Content) status.
class LetsEncryptNonceNew(LetsEncryptResource):

    def __init__(self, url, name = "newNonce"):
        super(LetsEncryptNonceNew, self).__init__(name, url)

    def send(self, data = None):
        return super(LetsEncryptNonceNew, self).info()

# Servers MUST NOT respond to GET requests for account resources as these
# requests are not authenticated.  If a client wishes to query the server for
# information about its account (e.g., to examine the "contact" or "orders"
# fields), then it SHOULD do so by sending a POST request with an empty update.
# That is, it should send a JWS whose payload is an empty object ({}).
# https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3.3
class LetsEncryptAccount(LetsEncryptResource):

    def __init__(self, url, name = "reg"):
        super(LetsEncryptAccount, self).__init__(name, url)

    def payload(self, email = None, agreement = None ):
        payload = {}
        return json.dumps(payload)

# https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3
class LetsEncryptAccountNew(LetsEncryptResource):

    def __init__(self, url, name = "newAccount"):
        super(LetsEncryptAccountNew, self).__init__(name, url)

    def payload(self, email = None, agreement = None ):
        payload = { "resource": self.getName() }

        # contact (optional, array of string): An array of URLs that the server
        # can use to contact the client for issues related to this account. For
        # example, the server may wish to notify the client about server-
        # initiated revocation or certificate expiration.
        # The server SHOULD validate that the contact URLs in the "contact"
        # field are valid and supported by the server. If the server validates
        # contact URLs it MUST support the "mailto" scheme. Clients MUST NOT
        # provide a "mailto" URL in the "contact" field that contains "hfields"
        # [RFC6068], or more than one "addr-spec" in the "to" component. If a
        # server encounters a "mailto" contact URL that does not meet these
        # criteria, then it SHOULD reject it as invalid.
        if email:
            payload["contact"] = [ "mailto:%s" % email ]

        # termsOfServiceAgreed (optional, boolean):  Including this field in a
        # new-account request, with a value of true, indicates the client's
        # agreement with the terms of service.  This field is not updateable
        # by the client.
        payload["termsOfServiceAgreed"] = True

        return json.dumps(payload)

    def send(self, data = None):
        response = super(LetsEncryptAccountNew, self).send(data)
        if response:
            if response.getStatus() == 201:
                self["reg"] = response["Location"]
                links = response["Link"]
                if isinstance(links, list):
                    ( self["linkagreement"], ) = [ u.split(';')[0].strip("<>") for u in links if "terms-of-service" in u ]
                elif "terms-of-service" in links:
                    self["linkagreement"] = links.split(';')[0].strip("<>")
        return response

# If the server already has an account registered with the provided account key,
# then it MUST return a response with a 200 (OK) status code and provide the URL
# of that account in the Location header field. This allows a client that has an
# account key but not the corresponding account URL to recover the account URL.
# If a client wishes to find the URL for an existing account and does not want
# an account to be created if one does not already exist, then it SHOULD do so
# by sending a POST request to the new-account URL with a JWS whose payload has
# an "onlyReturnExisting" field set to "true" ({"onlyReturnExisting": true}).
# If a client sends such a request and an account does not exist, then the
# server MUST return an error response with status code 400 (Bad Request) and
# type "urn:ietf:params:acme:error:accountDoesNotExist".
# https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-7.3.1
class LetsEncryptAccountFinding(LetsEncryptResource):

    def __init__(self, url, name = "newAccount"):
        super(LetsEncryptAccountFinding, self).__init__(name, url)

    def payload(self, email = None, agreement = None ):

        # onlyReturnExisting (optional, boolean):  If this field is present with
        # the value "true", then the server MUST NOT create a new account if one
        # does not already exist.  This allows a client to look up an account
        # URL based on an account key (see Section 7.3.1).
        payload["onlyReturnExisting"] = True

        return json.dumps(payload)

# ACMEv1
# https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-6.3
class LetsEncryptRegistration(LetsEncryptResource):

    def __init__(self, url, name = "reg"):
        super(LetsEncryptRegistration, self).__init__(name, url)

    def payload(self, email = None, agreement = None ):
        payload = { "resource": self.getName() }
        if email:
            payload["contact"] = [ "mailto:%s" % email ]
        # first priority is value porvided via parameters
        agreement = agreement or self["linkagreement"]
        if agreement:
            payload["agreement"] = agreement
        return json.dumps(payload)

# ACMEv1
class LetsEncryptRegistrationNew(LetsEncryptRegistration):

    def __init__(self, url):
        super(LetsEncryptRegistrationNew, self).__init__(url, "new-reg")

    def send(self, data = None ):
        response = super(LetsEncryptRegistrationNew, self).send(data)
        if response:
            self["reg"] = response["Location"]
            if response.getStatus() == 201:
                links = response["Link"]
                if isinstance(links, list):
                    ( self["linkagreement"], ) = [ u.split(';')[0].strip("<>") for u in links if "terms-of-service" in u ]
                elif "terms-of-service" in links:
                    self["linkagreement"] = links.split(';')[0].strip("<>")
        return response

class LetsEncryptAuthorization(LetsEncryptResource):

    def __init__(self, url, name = "authz"):
        super(LetsEncryptAuthorization, self).__init__(name, url)

    def payload(self, domain = None):
        payload = { "resource": self.getName() }
        if domain:
            payload["identifier"] = { "type": "dns", "value": domain }
        return json.dumps(payload)

# https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-6.5
class LetsEncryptAuthorizationNew(LetsEncryptAuthorization):

    def __init__(self, url):
        super(LetsEncryptAuthorizationNew, self).__init__(url, "new-authz")

    def send(self, data = None ):
        response = super(LetsEncryptAuthorizationNew, self).send(data)
        if response:
            self["authz"] = response["Location"]
        return response

# https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-6.5
class LetsEncryptAuthorizationCheck(LetsEncryptAuthorization):

    def __init__(self, url):
        super(LetsEncryptAuthorizationCheck, self).__init__(url)

    def payload(self):
        return None

class LetsEncryptChallenge(LetsEncryptResource):

    def __init__(self, url):
        super(LetsEncryptChallenge, self).__init__("challenge", url)

    def payload(self, keyAuthorization, challenge):
        payload = { "resource": self.getName(), "type": challenge }
        return payload

class LetsEncryptChallengeDNS(LetsEncryptChallenge):

    def __init__(self, url):
        super(LetsEncryptChallengeDNS, self).__init__(url)

    def payload(self, keyAuthorization):
        payload = super(LetsEncryptChallengeDNS, self).payload(keyAuthorization, "dns-01")
        payload["keyAuthorization"] =  keyAuthorization
        return json.dumps(payload)

class LetsEncryptCertificateIssuance(LetsEncryptResource):

    def __init__(self, url):
        super(LetsEncryptCertificateIssuance, self).__init__("new-cert", url)

    def payload(self, csr, period = 365):
        stamp = time.time()
        # today + period
        notBefore = self.stamp(stamp, formats = SSL_DATETIME_FORMAT)
        notAfter = self.stamp(stamp + period * 24 * 3600, formats = SSL_DATETIME_FORMAT)

        csr = self.base64urlencode(csr)

        payload = { "resource": self.getName(), "csr": csr, "notBefore": notBefore, "notAfter": notAfter }
        return json.dumps(payload)

    def send(self, data = None):
        response = super(LetsEncryptCertificateIssuance, self).send(data)
        if response:
            if response.getStatus() == 201:
                if response["Content-Type"] == "application/pkix-cert":
                    crt = response.getBody()
                    self["crt"] = self.base64urlencode(crt)
                    self["uri"] = response["Location"]
        return response

class LetsEncryptCertificateRevoke(LetsEncryptResource):

    def __init__(self, url):
        super(LetsEncryptCertificateRevoke, self).__init__("revoke-cert", url)

    def payload(self, crt):

        crt = self.base64urlencode(crt)

        payload = { "resource": self.getName(), "certificate": crt, "reason": 1 }
        return json.dumps(payload)

class LetsEncrypt(BaseUtils, LogInterface):

    config = None
    signer = None
    directory = None
    sslobject = None

    # always should consist last nonce returned by ACME service
    nonce = None
    kid = None

    def __init__(self, domain, config = None):
        super(LetsEncrypt, self).__init__()
        self.signer = RS256Signer()
        self.config = DomainConfig(domain, config)
        self.directory = LetsEncryptDirectory()
        self.sslobject = SSLObject()

    # check if key file exists and generate new one if not
    def getKey(self, bits = DEFAULT_KEY_SIZE):
        # get preconfigured settings
        key = self.config.key()

        try:
            # if field does not exist - raise TypeError
            bits = int(self.config.key("bits"))
        except TypeError:
            pass

        self.signer.loadPrivate(key)
        # key is loaded if we have its modulus and exponent available
        if self.signer.modulus():
            bits = self.signer.size()
        else:
            self.signer.generate(bits)
            key = self.signer.exportPrivate()
            # update config with actual data
            self.config.setKey(key)
        self.config.setKey(bits, "bits")
        return key

    def send(self, resource, *args):
        # debug
        self.setLogEntry("send")

        # additional JWS protected headers according to
        # https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-6.2
        fields = {}
        if self.nonce:
            fields["nonce"] = self.nonce
        if "url" in resource:
            fields["url"] = resource["url"]
        if self.kid:
            fields["kid"] = self.kid

        payload = resource.payload(*args)

        jws = None
        if isinstance(payload, basestring):
            jws = self.JWS(payload, fields)
            self.debug("payload: %s" % payload)
            self.debug("jws: %s" % jws)

        response = resource.send(jws)

        # update nonce after each sent request
        self.__updateNonce(resource)
        self.__updateKID()

        if isinstance(response, WebResponse):
            self.warn("resource name: %s" % resource.getName())
            self.warn("response status: %s" % response.getStatus())
            if "Content-Type" in response \
                    and (response["Content-Type"] in ("application/json",
                                                  "application/problem+json") \
                    or "text/plain" in response["Content-Type"]):
                self.warn("response body:\n%s" % response.getBody())
            for f in response:
                self.debug("hdr: %s: %s" % (f, response[f]))
        for f in resource:
            self.debug("data: %s: %s" % (f, resource[f]))
        return response

    # The "Replay-Nonce" header field includes a server-generated value that the
    # server can use to detect unauthorized replay in future client requests.
    # The server should generate the value provided in Replay-Nonce in such a
    # way that they are unique to each message, with high probability.
    # The value of the Replay-Nonce field MUST be an octet string encoded
    # according to the base64url encoding described in Section 2 of [RFC7515].
    # Clients MUST ignore invalid Replay-Nonce values.
    #   base64url = [A-Z] / [a-z] / [0-9] / "-" / "_"
    #   Replay-Nonce = *base64url
    # The Replay-Nonce header field SHOULD NOT be included in HTTP request
    # messages.
    # https://tools.ietf.org/html/draft-ietf-acme-acme-01#section-5.5.1
    #
    # nonce should be always up to date, therefore parameter response provides
    # posibility to set nonce based on another operation response
    def getNonce(self):
        nonce = LetsEncryptNonceNew(self.directory)
        return self.send(nonce)

    def __updateNonce(self, resource):
        if isinstance(resource, LetsEncryptResource) and resource["nonce"]:
            self.nonce = resource["nonce"]

    def __updateKID(self):
        if "reg" in self.directory and not self.kid:
            self.kid = self.directory["reg"]

    # def init(self, ctyp = "dns-01"):
    def init(self):
        # get RSA private key (generate if not exists)
        self.getKey()
        # get ACME directory data
        self.send(self.directory)
        # get new nonce
        self.getNonce()
        # propagate registration and uthorization URLs (if already set)
        for r in ("authz", "reg"):
            url = self.config.domain(r)
            if url:
                self.directory[r] = url
        self.__updateKID()


    def getCSR(self, subj = None, bits = DEFAULT_KEY_SIZE):

        # provided subject has more priority than stored in config
        # but if CSR stored inside configuration file - provided subject will
        # be ignored anyway
        if not isinstance(subj, basestring):
            subj = self.config.certificate('subj')

        # private key
        pkey = self.config.certificate('key')
        try:
            # if field does not exist - raise TypeError
            bits = int(self.config.certificate("bits"))
        except TypeError:
            pass
        if isinstance(pkey, basestring) and pkey:
            self.sslobject.loadPrivateKey(pkey)
        else:
            # generate and store into config
            self.sslobject.generateKey(bits)
            self.config.setCertificate(self.sslobject.getKey(), "key")
            self.config.setCertificate(bits, "bits")

        # certificate signing request
        csr = self.config.certificate('csr')
        if isinstance(csr, basestring) and csr:
            self.sslobject.loadCertificateRequest(csr)
            subj = self.sslobject.getCSRSubject()
        elif isinstance(subj, basestring):
            self.sslobject.generateCSR(subj)
            self.config.setCertificate(self.sslobject.getCSR(), "csr")
        else:
            return None
        self.config.setCertificate(subj, "subj")

        return self.sslobject.getCSR()

    def joseHeader(self):
        return self.signer.joseHeader()

    # The JWS Protected Header MUST include the following fields:
    # * "alg" (Algorithm)
    # * "jwk" (JSON Web Key, for all requests not signed using an existing
    #   account, e.g. newAccount)
    # * "kid" (Key ID, for all requests signed using an existing account)
    # * "nonce" (defined in Section 6.4 below)
    # * "url" (defined in Section 6.3 below)
    #
    # https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-6.2
    def JWSProtectedHeader(self, fields):
        header = self.joseHeader()
        if isinstance(fields, dict):
            for f in ['kid', 'nonce', 'url']:
                if f in fields:
                    header[f] = fields[f]
            # The "jwk" and "kid" fields are mutually exclusive. Servers MUST
            # reject requests that contain both.
            # For newAccount requests, and for revokeCert requests authenticated
            # by certificate key, there MUST be a "jwk" field.  This field MUST
            # contain the public key corresponding to the private key used to
            # sign the JWS.
            # For all other requests, the request is signed using an existing
            # account and there MUST be a "kid" field.  This field MUST contain
            # the account URL received by POSTing to the newAccount resource.
            if 'kid' in header:
                del header['jwk']
        return json.dumps(header)

    # ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    # BASE64URL(JWS Payload)).
    def JWSSigningInput(self, payload, fields):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        return self.base64urlencode(self.JWSProtectedHeader(fields)) + "." + self.base64urlencode(payload)

    def JWSSignature(self, payload, fields):
        signInput = self.JWSSigningInput(payload, fields)
        rawSignature = self.signer.sign(signInput)
        if rawSignature:
            return self.base64urlencode(rawSignature)
        return None

    # * The JWS MUST be in the Flattened JSON Serialization
    # * The JWS MUST NOT have multiple signatures
    # * The JWS Unencoded Payload Option [RFC7797] MUST NOT be used
    #   https://tools.ietf.org/html/rfc7797#section-3
    # * The JWS Unprotected Header MUST NOT be used
    # * The JWS The JWS Payload MUST NOT be detached
    #   https://tools.ietf.org/html/rfc7515#appendix-F
    #
    # https://tools.ietf.org/html/draft-ietf-acme-acme-10#section-6.2
    def JWS(self, payload, fields = None):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        jws = {
            "payload": self.base64urlencode(payload),
            "protected": self.base64urlencode(self.JWSProtectedHeader(fields)),
            "signature": self.JWSSignature(payload, fields)
        }
        return json.dumps(jws)

    # https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.4
    # A client responds to this challenge by constructing a key authorization
    # from the "token" value provided in the challenge and the client's account
    # key.  The client then computes the SHA-256 digest of the key
    # authorization. The record provisioned to the DNS is the base64url
    # encoding of this digest.
    # https://tools.ietf.org/html/draft-ietf-acme-acme-03#section-7.1
    # key-authz = token || '.' || base64url(JWK_Thumbprint(accountKey))
    def keyAuthorization(self, ctyp = "dns-01"):
        if ctyp in self.config:
            return self.config[ctyp]["token"] + "." + self.base64urlencode(self.signer.JWKThumbprint())
        return None

    # The server creates a registration object with the included contact
    # information. The “key” element of the registration is set to the public
    # key used to verify the JWS (i.e., the “jwk” element of the JWS header).
    # The server returns this registration object in a 201 (Created) response,
    # with the registration URI in a Location header field. The server MUST
    # also indicate its new-authorization URI using the “next” link relation.
    # If the server wishes to present the client with terms under which the
    # ACME service is to be used, it MUST indicate the URI where such terms can
    # be accessed in a Link header with link relation “terms-of-service”. As
    # noted above, the client may indicate its agreement with these terms by
    # updating its registration to include the “agreement” field, with the
    # terms URI as its value.
    # ACMEv1
    def register(self, email = None):
        # check and set
        if isinstance(email, basestring):
            if not self.config.setContact(email):
                return None
        if self.config.contact():
            newreg = LetsEncryptRegistrationNew(self.directory)
            response = self.send(newreg, email)
            status = None
            if response:
                status = response.getStatus()
            # store received data to configuration file
            if status in (201, 409):
                p = "reg"
                self.config.setDomain(newreg[p], p)
                # add registration URI into directory object manually
                self.directory[p] = newreg[p]
                if status == 201:
                    for p in ("initialIp", "createdAt", "id"):
                        self.config.setDomain(newreg[p], p)
                    p = "linkagreement"
                    self.config.setContact(newreg[p], p)
                    # accept agreement
                    self.agreement()
            return status
        return None

    def registerV2(self, email = None):
        # check and set
        if isinstance(email, basestring):
            if not self.config.setContact(email):
                return None
        if self.config.contact():
            newreg = LetsEncryptAccountNew(self.directory)

            # For newAccount requests, and for revokeCert requests authenticated
            # by certificate key, there MUST be a "jwk" field.
            self.kid = None

            response = self.send(newreg, email)
            status = None
            if response:
                status = response.getStatus()
            # store received data to configuration file
            if status in (201, 409):
                p = "reg"
                self.config.setDomain(newreg[p], p)
                # add registration URI into directory object manually
                self.directory[p] = newreg[p]
                if status == 201:
                    for p in ("initialIp", "createdAt", "id"):
                        self.config.setDomain(newreg[p], p)
                    p = "linkagreement"
                    self.config.setContact(newreg[p], p)
            return status
        return None

    # ACME v1
    def agreement(self):
        reg = LetsEncryptRegistration(self.directory)
        response = self.send(reg, self.config.contact(), self.config.contact("linkagreement"))
        status = None
        if response:
            status = response.getStatus()
        if status == 202:
            p = "agreement"
            self.config.setContact(reg[p], p)
            del(self.config["contact"]["linkagreement"])
        return status

    def checkRegistration(self):
        reg = LetsEncryptRegistration(self.directory)
        response = self.send(reg)
        status = None
        if response:
            status = response.getStatus()
        return status

    def checkRegistrationV2(self):
        reg = LetsEncryptAccount(self.directory)
        response = self.send(reg)
        status = None
        if response:
            status = response.getStatus()
        return status

    def authorization(self):
        auth = LetsEncryptAuthorizationNew(self.directory)
        response = self.send(auth, self.config.domain())
        status = None
        if response:
            status = response.getStatus()
        # if agreement is not accepted
        # if status == 403:
        #     if auth["type"] == "urn:acme:error:unauthorized":
        #         self.agreement()
        if status == 201:
            p = "authz"
            self.config.setDomain(auth[p], p)
            # add authorization URI into directory object manually
            self.directory["authz"] = auth[p]
            # challenges
            for p in ("status", "expires"):
                self.config.setChallenges(auth[p], p)
            challenges = auth["challenges"]
            # store supported challenges types
            self.config.setChallenges(",".join([ c["type"] for c in challenges ]))
            # store challenges
            for c in challenges:
                self.config[c["type"]] = c
        return status

    def checkAuthorization(self):
        authz = LetsEncryptAuthorizationCheck(self.directory)
        response = self.send(authz)
        status = None
        if response:
            status = response.getStatus()
        if status == 200:
            # challenges
            for p in ("status", "expires"):
                self.config.setChallenges(authz[p], p)
            challenges = authz["challenges"]
            for c in challenges:
                name = c["type"]
                for p in ("type", "status", "uri", "token"):
                    if p in c:
                        self.config.setOption(name, p, c[p])
        return status

    # The validation object covered by the signature MUST have the following
    # fields and no others:
    #
    # type (required, string):      The string “dns”
    # token (required, string):     The token value from the server-provided
    #                               challenge object
    #    {
    #        "type": "dns",
    #        "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
    #    }
    #
    # The client serializes the validation object to UTF-8, then uses its
    # account private key to sign a JWS with the serialized JSON object as its
    # payload. This JWS is NOT REQUIRED to have the “nonce” header parameter.
    # def dnsRecord(self):
    #     # chellenge type is "dns-01"
    #     payload = { "type": "dns-01", "token": self.config.getOption("dns-01", "token") }
    #     # sign it
    #     signature = self.JWSSignature(payload, nonce = False)
    #     # _acme-challenge.example.com. 300 IN TXT "gfj9Xq...Rg85nM"
    #     return "_acme-challenge.%s.\tIN TXT\t\"%s\"" % ( self.config.domain(), signature)

    def dnsRecord(self):
        # chellenge type is "dns-01"
        keyauthz = self.keyAuthorization("dns-01")
        # sign it
        signature = self.base64urlencode(hashlib.sha256(keyauthz).digest())
        # _acme-challenge.example.com. 300 IN TXT "gfj9Xq...Rg85nM"
        return "_acme-challenge.%s.\tIN TXT\t%s" % ( self.config.domain(), signature)

    def challenge(self, ctyp = "dns-01"):
        if ctyp in self.config:
            url = self.config[ctyp]["uri"]
            challenge = LetsEncryptChallengeDNS(url)
            response = self.send(challenge, self.keyAuthorization(ctyp))
            status = None
            if response:
                status = response.getStatus()
            if status == 202:
                p = "status"
                self.config[ctyp][p] = challenge[p]
                return status
        return None

    def certificate(self, subj = None, bits = DEFAULT_KEY_SIZE):

        if not (isinstance(subj, basestring) and "/CN=" in subj):
            subj = "/CN=%s" % self.config.domain()

        # load or generate CSR
        self.getCSR(subj, bits)

        # check if CSR exists - exit if not
        csr = self.config.certificate('csr')
        if not csr:
            return None

        cert = LetsEncryptCertificateIssuance(self.directory)
        response = self.send(cert, csr)
        status = None
        if response:
            status = response.getStatus()
        if status == 201:
            for p in ("uri", "crt"):
                self.config.setCertificate(cert[p], p)
        return status

    def revoke(self, cert = None):
        data = self.config.certificate()
        # we suppose that there are single key inside config and several
        # certificates exist (which we can get from https://crt.sh)
        if isinstance(cert, basestring) and cert:
            self.sslobject.loadCertificate(cert)
            data = self.sslobject.getCert()
        if not data:
            return None
        # load SSL key into signer object
        sslkey = self.config.certificate("key")
        self.signer.loadPrivate(sslkey)

        revoke = LetsEncryptCertificateRevoke(self.directory)
        response = self.send(revoke, data)
        status = None
        if response:
            status = response.getStatus()
        if status == 200:
            if not cert:
                for p in ("crt", "uri"):
                    del(self.config["certificate"][p])
        return status

    def saveCert(self, form = "PEM", path = None):
        # current directory is default directory to save
        basedir = "."
        if isinstance(path, basestring) and path:
            basedir = path
        for p in ("crt", "key"):
            data = self.config.certificate(p)
            if not data:
                continue
            path = basedir + "/" + self.config.domain() + "." + p
            fh = self.openfile(path, "w")
            if not fh:
                return
            if form == "PEM":
                if p == "crt":
                    self.sslobject.loadCertificate(data)
                    data = self.sslobject.getCert("PEM")
                elif p == "key":
                    self.sslobject.loadPrivateKey(data)
                    data = self.sslobject.getKey("PEM")
            fh.write(data)
            fh.close()

    def __del__(self):
        if self.config:
            self.config.save()
