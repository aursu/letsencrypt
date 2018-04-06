#!/usr/bin/python

import re
import urllib2, urllib, httplib, socket
from utils import UtilsCI
import cookielib
import os.path
from StringIO import StringIO
import select
import gzip

# maximum attemps count to send request to server
MAXATTEMPTS = 5
SOCKTIMEOUT = 5

class HTTPMessage(UtilsCI):

    # An HTTP message can be either a request from client to server or a
    # response from server to client.  Syntactically, the two types of message
    # differ only in the start-line, which is either a request-line (for
    # requests) or a status-line (for responses)
    # https://tools.ietf.org/html/rfc7230#section-3.1
    __startLine = None

    # https://tools.ietf.org/html/rfc7230#section-3.3
    __body = None
    __version = "1.1"    # HTTP-version

    def __init__(self):
        super(HTTPMessage,self).__init__()

    def startLine(self):
        return self.__startLine

    def setStartLine(self, data):
        if isinstance(data, basestring) and data:
            self.__startLine = data
        return self

    def getBody(self):
        return self.__body

    # return HTTP message body size
    def bodySize(self):
        if isinstance(self.__body, basestring):
            return len(self.__body)
        return 0

    def setBody(self, data):
        if isinstance(data, basestring) and len(data):
            self.__body = data
        return self

    # return HTTP version
    def getVersion(self):
        return self.__version

    def setVersion(self, version):
        if (isinstance(version, basestring) and version) or \
                                                    version in (1, 1.0, 1.1, 2):
            if version in ("1.0", 1, 1.0):
                self.__version = "1.0"
            if version in ("1.1", 1.1):
                self.__version = "1.1"
            elif version in ("2", "2.0", 2):
                self.__version = "2"
        return self

    # set HTTP header
    def set(self, header, value):
        # headers could not be empty: no value - no header
        # support integer 0 as wells
        if value or isinstance(value, int):
            super(HTTPMessage, self).set(header, str(value))
        return self

    # https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.2
    # Multiple message-header fields with the same field-name MAY be present in
    # a message if and only if the entire field-value for that header field is
    # defined as a comma-separated list [i.e., #(values)]. It MUST be possible
    # to combine the multiple header fields into one "field-name: field-value"
    # pair, without changing the semantics of the message, by appending each
    # subsequent field-value to the first, each separated by a comma. The order
    # in which header fields with the same field-name are received is therefore
    # significant to the interpretation of the combined field value, and thus a
    # proxy MUST NOT change the order of these field values when a message is
    # forwarded.
    def add(self, h, value):
        if isinstance(h, basestring) and h:
            # headers could not be empty: no value - no header
            if value or isinstance(value, int):
                # headers names are case-insensitive
                if h in self:
                    if isinstance(self[h], list):
                        self[h] += [str(value)]
                    else:
                        header = [self[h], str(value)]
                        super(HTTPMessage, self).set(h, header)
                else:
                    self.set(h, value)
        return self

    def reset(self):
        self.__startLine = None
        self.__body = None
        self.__version = "1.1"
        super(HTTPMessage, self).reset()

# POST or GET key-value parameters
class WebData(UtilsCI):

    def __init__(self):
        super(WebData, self).__init__()

    # python None is empty string s
    def set(self, key, value):
        if value is None:
            value = ""
        super(WebData, self).set(key, str(value))
        return self

    def getRaw(self):
        rawdata = ""
        for i in self:
            v = ""
            if self[i] is not None:
                v = str(self[i])
            rawdata += "&" + i + "=" + v
        if rawdata:
            # remove first character '&'
            return rawdata[1:]
        return rawdata

    def getURLEncoded(self):
        encdata = ""
        for i in self:
            v = ""
            if self[i] is not None:
                v = str(self[i])
            encdata += "&" + urllib2.quote(i) + "=" + urllib2.quote(v)
        if encdata:
            # remove first character '&'
            return encdata[1:]
        return encdata

# POST data could be not only key-value but Raw as well
class POSTData(WebData):
    """ Add ability to store Raw data (not only Key-Value) inside POST object
    If both Raw and Key-Value exist - Raw has higher priority (Key-Value data
    will be ignored)"""

    __data = ""

    def __init__(self):
        super(POSTData, self).__init__()

    # redefine object length to raw data length
    def __len__(self):
        return len(self.__data)

    def getData(self):
        if len(self):
            return self.__data
        # default is return URL-Encoded POST data if no Raw data set
        return self.getURLEncoded()

    def setData(self, data):
        if isinstance(data,  basestring) and data:
            self.__data = data
        return self

    def reset(self):
        self.__data = ""
        super(POSTData, self).reset()

# WebService is object which responsible for connection using particular scheme
# to specified port (by default - using https to 443 port)
class WebService(object):
    __scheme = "https"
    __port = 443

    def __init__(self):
        super(WebService, self).__init__()

    def scheme(self):
        return self.__scheme

    def port(self):
        return self.__port

    def secure(self, flag = True):
        if isinstance(flag, bool) and not flag:
            self.__scheme = "http"
        else:
            self.__scheme = "https"
        return self

    def setPort(self, port = 0):
        if isinstance(port, int) and port >= 1 and port <= 65535:
            self.__port = port
        elif self.scheme() == "https":
            self.__port = 443
        else:
            self.__port = 80
        return self

# interface which provide ability to store HTTP headers and propagate them into
# WEB request objects
class SetupHeadersInterface(object):

    __headers = None

    def __init__(self):
        super(SetupHeadersInterface, self).__init__()
        self.__headers = HTTPMessage()

    # Ability to have WebResource specific headers
    def addHeader(self, name, value):
        self.__headers.add(name, value)
        return self

    # setup headers into Request object
    def __setupHeader(self, request, name, value):
        # WebRequest is child of HTTPMessage
        if isinstance(request, WebRequest):
            request[name] = value
        elif isinstance(request, urllib2.Request):
            if isinstance(value, list):
                request.add_header(name, ",".join(value))
            else:
                request.add_header(name, value)

    def setupHeaders(self, request):
        for h in self.__headers:
            self.__setupHeader(request, h, self.__headers[h])
        return self

# WebSite is object which responsible for connection to specific host/site
class WebSite(WebService, SetupHeadersInterface):

    __hostname = None

    def __init__(self, hostname = "localhost"):
        super(WebSite, self).__init__()
        self.setHost(hostname)

    def getHost(self):
        return self.__hostname

    def getURL(self):
        url = "%s://%s" % (self.scheme(), self.__hostname)
        if self.port() in (80, 443):
            return url
        return "%s:%s" % (url, self.port())

    # default hostname is "localhost", hostname should be defined for WebService
    def setHost(self, hostname):
        if isinstance(hostname, basestring) and hostname:
            hostname = hostname.lower()
            checker = re.compile("^([a-z0-9]+([a-z0-9-]*[a-z0-9])*)((\.[a-z0-9]+([a-z0-9-]*[a-z0-9])*)*(\.([a-z]{2,}|xn--[a-z0-9]{2,})))?$", re.I)
            if checker.match(hostname) is not None:
                self.__hostname = hostname
                # website specific header
                self.addHeader("Host", self.__hostname)
                return self
        self.__hostname = "localhost"
        self.addHeader("Host", "localhost")
        # localhost could not be secure by default
        self.secure(False)
        return self

# WebResource is object which responsible for connection to separate URL path on
# Web site
class WebResource(WebSite):

    __path = "/"

    def __init__(self, host = "localhost", path = "/"):
        super(WebResource, self).__init__(host)
        self.setPath(path)

    def getPath(self):
        return self.__path

    def setPath(self, path):
        if isinstance(path, basestring) and path:
            self.__path = "/" + path.lstrip("/")
        else:
            self.__path = "/"
        return self

    # support for linkig WebSite into WebResource
    def linkTo(self, website):
        if isinstance(website, WebSite):
            self.setHost(website.getHost())
            if website.scheme() == "http":
                self.secure(False)
            self.setPort(website.port())
        else:
            raise TypeError("Inappropriate argument type for website.")
        return self

    # return URL of Web site we connect to (ie https://domain.com)
    def getSiteURL(self):
        return super(WebResource, self).getURL()

    def addComponent(self, subpath):
        if isinstance(subpath, basestring) and subpath:
            self.__path = self.__path.rstrip("/") + "/" +  subpath.lstrip("/")
        return self

    # return Web resource URL (ie https://domain.com/some/path)
    def getURL(self):
        return self.getSiteURL() + self.__path

    # Web resource URL parser
    # Expected are:
    # http://domain.tld/resource?parameters#fragment
    # https://domain.tld/resource?parameters#fragment
    # domain.tld/resource?parameters#fragment
    # default path - "/"
    def setURL(self, webresource):
        if isinstance(webresource, basestring) and webresource:
            url = webresource.lower()

            secure = None
            # check if path is full URL
            if "http://" in url:
                secure = False
            elif "https://" in url:
                secure = True

            if isinstance(secure, bool):
                self.secure(secure)
                # remove protocol schme part
                url = webresource[url.index("//") + 2:]
            else:
                # return back to original case
                url = webresource

            host = None     # default behaviour is "http://localhost"
            path = "/"
            if "/" in url:
                delim = url.index("/")
                # remove hostname part
                if delim > 0:
                    host = url[:delim]
                path = url[delim:]
            else:
                host = url

            delim = ((path.find("?") + 1) or (path.find("#") + 1)) - 1
            if delim > 0:
                path = path[:delim]

            self.setHost(host)
            self.setPath(path)
        return self

class WebResourceInterface(object):

    __resource = None

    def __init__(self):
        super(WebResourceInterface, self).__init__()

    def linkTo(self, webresource):
        if isinstance(webresource, WebResource):
            self.__resource = webresource
        elif isinstance(webresource, basestring) and webresource:
            self.__resource = WebResource()
            self.__resource.setURL(webresource)
        else:
            raise TypeError("Inappropriate argument type for web resource.")
        return self

    def resource(self):
        return self.__resource

    def unlink(self):
        self.__resource = None
        return self

    def __del__(self):
        pass

# WebRequest should know WebResource to which it will be submitted
class WebRequest(HTTPMessage, WebResourceInterface):
    __method = "GET"
    __get = None
    __post = None

    # we can not compile WEB Request withouth URL path
    __path = "/"

    def __init__(self):
        super(WebRequest, self).__init__()
        self.__post = POSTData()
        self.__get = WebData()

    def __updateMessage(self):
        self.setStartLine("%s %s HTTP/%s" % (self.__method, self.getPath(), self.getVersion()))

    def __setMethod(self, request):
        # default methods should not be handled
        if self.__method not in ( "GET", "POST" ):
            if isinstance(request, urllib2.Request):
                request.get_method = lambda : self.__method
        return request

    def setVersion(self, version):
        super(WebRequest, self).setVersion(version)
        self.__updateMessage()
        return self

    def getMethod(self):
        return self.__method

    def setMethod(self, meth):
        if isinstance(meth, basestring) and meth:
            if meth.upper() in ( "GET", "POST", "HEAD" ):
                self.__method = meth.upper()
                self.__updateMessage()
        return self

    def getParams(self):
        return self.__get

    def getData(self):
        return self.__post

    def setData(self, data):
        self.__post.setData(data)

    def getPath(self):
        # we do not want to add this to path (and therefore duplicate data)
        if self.__get.getRaw():
            return self.__path + "?" + self.__get.getURLEncoded()
        return self.__path

    def setPath(self, path):
        if isinstance(path, basestring) and path:
            self.__path = "/" + path.lstrip("/")
            self.__updateMessage()
        return self

    def getURL(self):
        if self.resource():
            return self.resource().getSiteURL() + self.getPath()
        return None

    def addPOST(self, name, value):
        self.__post[name] = value
        self.setMethod("POST")
        return self

    def addGET(self, name, value):
        self.__get[name] = value
        self.__updateMessage()
        return self

    def delGET(self, name):
        del self.__get[name]
        self.__updateMessage()
        return self

    def delPOST(self, name):
        del self.__post[name]
        return self

    def linkTo(self, webresource):
        super(WebRequest, self).linkTo(webresource)
        self.setPath(self.resource().getPath())
        return self

    def unlink(self):
        super(WebRequest, self).unlink()
        self.setPath("/")
        return self

    # returns urllib2.Request object
    def prepare(self, webresource = None):
        # link request to provided resource if specified
        if webresource:
            self.linkTo(webresource)

        # prepare urllib2.Request object
        r = urllib2.Request(self.getURL())

        # propagate headers
        for h in self:
            r.add_header(h, self[h])

        # propagate body from POST data
        self.setBody()
        if self.bodySize():
            r.add_data(self.getBody())

        return self.__setMethod(r)

    def setBody(self):
        # Raw data if set or URL-Encoded data if not
        return super(WebRequest, self).setBody(self.__post.getData())

    # http://www.amazon.com/review/product/B00OO3OZYG?SubscriptionId=AKIAJYAW23VXUFYJ3XCQ&tag=nkawus-20&linkCode=xm2&camp=2025&creative=386001&creativeASIN=B00OO3OZYG
    def setURL(self, url):
        if isinstance(url, basestring) and url:
            request = None
            if "?" in url:
                delim = url.index("?")
                request = url[delim + 1:]
            if request:
                url = url[:delim]
                # parse request line
                params = request.split("&")
                for p in params:
                    v = ""
                    n = p
                    if "=" in p:
                        n, v = p.split("=", 1)
                    self.addGET(urllib2.unquote(n), urllib2.unquote(v))
            # check if resource alredy linked to request
            if self.resource():
                self.resource().setURL(url)
                # we need relink resource becase linkTo operation has custom
                # rules for most web requests objects
                self.linkTo(self.resource())
            else:
                self.linkTo(url)
            return self
        return None

class WebResponse(HTTPMessage):
    __status = None
    __reason = None

    def __init__(self):
        super(WebResponse, self).__init__()

    def getstatus(self):
        return self.__status

    def getreason(self):
        return self.__reason

    def encoding(self):
        if "Content-Encoding" in self:
            return self["Content-Encoding"]
        return None

    def setreason(self, phrase):
        if isinstance(phrase, basestring) and phrase:
            self.__reason = phrase
            if self.__status:
                self.setStartLine("HTTP/%s %s %s" % (self.getVersion(), self.__status, self.__reason))
        return self

    def setstatus(self, code):
        # cheack if provided code is number
        try:
            code = int(code)
            # https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html
            # https://tools.ietf.org/html/rfc2774.html
            if code >= 100 and code <= 510:
                self.__status = code
        except TypeError:
            return self
        # update HTTP message for currnt object
        # check if provided code message is known to us
        # at least known to python (https://docs.python.org/2/library/httplib.html)
        if self.__status and self.__status in httplib.responses:
            self.setStartLine("HTTP/%s %s %s" % (self.getVersion(), self.__status, httplib.responses[self.__status]))
        return self

    def populate(self, response):
        self.reset()
        # urllib2 response object is instance of urllib.addinfourl class
        if isinstance(response, urllib.addinfourl):
            # set Status-Code and Reason-Phrase
            self.setstatus(response.code)
            self.setreason(response.msg)
            # set headers
            # h.gettype() - Content-Type header value (no header - "text/plain")
            # h.getencoding() - Content-Transfer-Encoding header value (no header - "7bit")
            # h.headers - list of raw headers in order they were read
            # h iterator - iteration through headers (keys are lowered in case, values combined)
            h = response.info()
            if h.headers:
                for i in h.headers:
                    if ":" in i:
                        n, v = i.split(":", 1)
                        v = v.strip()
                        self.add(n, v)
            # check if body also should be get from response object
            try:
                # check if we have anything to read (response  consists method
                # fileno which is bound to original socket fileno method)
                select.select([response],[],[],0)
                # we will handle socket timeout on upper level where we can
                # submit request again
                # try:
                #     d = response.read()
                #     self.setBody(d)
                # except socket.timeout:
                #     pass
                d = response.read()
                self.setBody(d)
            except AttributeError:
                pass
        return self

    def reset(self):
        self.__status = None
        self.__reason = None
        super(WebResponse, self).reset()

    def setBody(self, data):
        # check if data gzip-compressed
        # \x1f\x8b is gzip (deflate) magic number
        if isinstance(data, basestring) and len(data) > 2 and data[:2] == "\x1f\x8b":
            data = self.__gunzip(data)
        return super(WebResponse, self).setBody(data)

    def __gunzip(self, data):
        gzfile = StringIO(data)
        gzstream = gzip.GzipFile(fileobj = gzfile)
        return gzstream.read()

COOKIESDIR = "/tmp"

class WebClient(WebResourceInterface, SetupHeadersInterface):

    __cookies = None
    __opener = None
    __response = None

    def __init__(self):
        super(WebClient, self).__init__()
        self.__response = WebResponse()

    def setAddress(self, webresource):
        super(WebClient, self).linkTo(webresource)
        # setup cookies
        self.__setCookies()
        # setup opener object to use cookies
        self.__opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.__cookies))
        return self

    # return urllib2 response object if request was successfull
    # return None if fail
    def sendRequest(self, webrequest):
        if not self.resource():
            raise ValueError("Web address is not specified. Use setAddress() to define it.")
        if not isinstance(webrequest, WebRequest):
            raise TypeError("Inappropriate argument type for web request.")

        # setup request headers
        self.setupHeaders(webrequest)

        u2request = webrequest.prepare(self.resource())

        u2response = None
        # reset response object to avoid undefined behavior in case of failed request
        self.__response.reset()

        attempt = 1
        while attempt <= MAXATTEMPTS:
            try:
                u2response = self.__opener.open(u2request, timeout = SOCKTIMEOUT)
                self.__response.populate(u2response)
                break
            except urllib2.HTTPError as r:
                if isinstance(r, urllib.addinfourl):
                    self.__response.populate(r)
                    break
                attempt += 1
            except (urllib2.URLError, socket.timeout, IOError):
                attempt += 1

        return self

    def setupHeaders(self, request):
        # if web resource has own specific headers
        self.resource().setupHeaders(request)
        # setup browser specific headers
        return super(WebClient, self).setupHeaders(request)

    def getStatus(self):
        return self.__response.getstatus()

    def getResponse(self):
        return self.__response

    def __setCookies(self):
        self.savecookies()
        cookiesfile = COOKIESDIR + "/" + self.resource().getHost() + ".txt"
        self.__cookies = cookielib.LWPCookieJar(cookiesfile)
        if os.path.isfile(cookiesfile):
            self.__cookies.load()

    def setUA(self, value):
        return self.addHeader("User-Agent", value)

    def setMTypes(self, value):
        return self.addHeader("Accept", value)

    def setConn(self, value = "keep-alive"):
        return self.addHeader("Connection", value)

    def setLang(self, value):
        return self.addHeader("Accept-Language", value)

    def setEnc(self, value):
        return self.addHeader("Accept-Encoding", value)

    def savecookies(self):
        if isinstance(self.__cookies, cookielib.CookieJar):
            self.__cookies.save()
        return self

    def __del__(self):
        self.savecookies()

class GoogleChrome(WebClient):

    def __init__(self):
        super(GoogleChrome, self).__init__()
        # Common headers
        self.setUA("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36")
        self.setMTypes("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        self.setConn()
        self.setLang("en-US,en;q=0.8")
        self.setEnc("gzip, deflate, sdch")
        # Google Chrome specific
        self.addHeader("Upgrade-Insecure-Requests", "1")
        self.addHeader("Cache-Control", "no-cache")
        self.addHeader("Pragma", "no-cache")

class GoogleChromeWindows(GoogleChrome):

    def __init__(self):
        super(GoogleChromeWindows, self).__init__()
        # Common headers
        self.setUA("User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36")

class WebInterface(object):

    ua = None
    resource = None
    request = None

    def __init__(self):
        super(WebInterface, self).__init__()
        self.resetWebTools()

    def sendRequest(self, data = None):
        # set data if provided (Raw data - non-POST)
        self.request.setData(data)

        self.request.linkTo(self.resource)

        self.ua.setAddress(self.request.resource())
        self.ua.sendRequest(self.request)

        resp = self.ua.getResponse()

        # if request was failed, status is not set
        if not resp.getstatus():
            return None

        return resp

    def resetWebTools(self):
        self.ua = GoogleChrome()
        self.resource = WebResource()
        self.request = WebRequest()

    def setURL(self, url):
        if isinstance(url, basestring) and url:
            self.resource.setURL(url)
            self.request.setURL(url)

    def __del__(self):
        pass
