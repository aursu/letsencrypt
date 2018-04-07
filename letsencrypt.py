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
class LetsEncryptACME(WebResource):
    def __init__(self):
        super(LetsEncryptACME, self).__init__("acme-v01.api.letsencrypt.org")
        # super(LetsEncryptACME, self).__init__("acme-staging.api.letsencrypt.org")
        self.secure(True)

# https://acme-v01.api.letsencrypt.org/directory
class ACMEDirectory(LetsEncryptACME):
    def __init__(self):
        super(ACMEDirectory, self).__init__()
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

        self.debug("resource name: %s" % name, "__init__")
        if isinstance(name, basestring) and name:
            self.__name = name

        # URL could be fetched by resource name from provided dictionary object
        if isinstance(url, Utils) or isinstance(url, dict):
            self.debug("\"%s\" in url: %s" % (self.__name, self.__name in url))
            if self.__name and self.__name in url:
                url = url[self.__name]

        if isinstance(url, basestring) and url:
            self.setURL(url)

    def getName(self):
        return self.__name

    def setNonce(self, response):
        if isinstance(response, WebResponse) and "Replay-Nonce" in response:
            self["nonce"] = response["Replay-Nonce"]

    # nonce should be always up to date, therefore parameter response provides
    # posibility to set nonce based on another operation response
    def getNonce(self, response = None):
        self.request.setMethod("HEAD")
        response = self.sendRequest()
        if not response:
            return None
        self["nonce"] = response["Replay-Nonce"]
        return self["nonce"]

    def send(self, data = None ):
        self.request.setMethod("GET")
        response = self.sendRequest(data)
        # if request was failed, status is not set
        if not isinstance(response, WebResponse):
            return None
        self.feed(response.getBody())
        self.setNonce(response)
        return response

    def payload(self):
        return None

class LetsEncryptDirectory(LetsEncryptResource):

    def __init__(self):
        super(LetsEncryptDirectory, self).__init__("directory")
        self.resource = ACMEDirectory()

    def send(self, data = None):
        super(LetsEncryptDirectory, self).send()
        return self.object()

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

class LetsEncryptRegistrationNew(LetsEncryptRegistration):

    def __init__(self, url):
        super(LetsEncryptRegistrationNew, self).__init__(url, "new-reg")

    def send(self, data = None ):
        response = super(LetsEncryptRegistrationNew, self).send(data)
        if response:
            self["reg"] = response["Location"]
            if response.getStatus() == 201:
                ( self["linkagreement"], ) = [ u.split(";")[0].strip("<>") for u in response["Link"] if "terms-of-service" in u ]
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
    # always should consist last nonce returned by ACME service
    nonce = None
    sslobject = None

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

        # self.signer.loadPrivate(kpath)
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
        self.setLogEntry("send")  # debug

        payload = resource.payload(*args)

        jws = None
        if isinstance(payload, basestring):
            jws = self.JWS(payload)
            self.debug("payload: %s" % payload)
            self.debug("jws: %s" % jws)
        response = resource.send(jws)
        # update nonce
        self.__updateNonce(resource)
        if isinstance(response, WebResponse):
            self.warn("resource name: %s" % resource.getName())
            self.warn("response status: %s" % response.getStatus())
            if response["Content-Type"] in ("application/json", "application/problem+json") \
                or "text/plain" in response["Content-Type"]:
                self.warn("response body:")
                self.warn(response.getBody())
            for f in response:
                self.debug("h: %s: %s" % (f, response[f]))
        for f in resource:
            self.debug("d: %s: %s" % (f, resource[f]))
        return response

    # def init(self, ctyp = "dns-01"):
    def init(self):
        # get RSA private key (generate if not exists)
        self.getKey()
        # get ACME directory data
        self.send(self.directory)
        # propagate registration and uthorization URLs (if already set)
        for r in ("reg", "authz"):
            url = self.config.domain(r)
            if url:
                self.directory[r] = url

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

    def JWSProtectedHeader(self, nonce = True):
        header = self.joseHeader()
        if nonce:
            header["nonce"] = self.nonce
        return json.dumps(header)

    # ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
    # BASE64URL(JWS Payload)).
    def JWSSigningInput(self, payload, nonce = True):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        return self.base64urlencode(self.JWSProtectedHeader(nonce)) + "." + self.base64urlencode(payload)

    def JWSSignature(self, payload, nonce = True):
        signInput = self.JWSSigningInput(payload, nonce)
        rawSignature = self.signer.sign(signInput)
        if rawSignature:
            return self.base64urlencode(rawSignature)
        return None

    def JWS(self, payload, nonce = True):
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        jws = {
            "payload": self.base64urlencode(payload),
            "protected": self.base64urlencode(self.JWSProtectedHeader()),
            "header": self.joseHeader(),
            "signature": self.JWSSignature(payload, nonce)
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

    def __updateNonce(self, resource):
        if isinstance(resource, LetsEncryptResource) and resource["nonce"]:
            self.nonce = resource["nonce"]

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
