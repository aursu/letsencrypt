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

    __message = None
    __body = None
    __version = "1.1"    # HTTP version

    def __init__(self):
        super(HTTPMessage,self).__init__()

    def getMessage(self):
        return self.__message

    def getBody(self):
        return self.__body

    # return HTTP message body size
    def bodySize(self):
        if isinstance(self.__body, basestring):
            return len(self.__body)
        return 0

    # return HTTP version
    def getVersion(self):
        return self.__version

    # set HTTP header
    def set(self, header, value):
        # headers could not be empty: no value - no header
        if value or isinstance(value, int):
            super(HTTPMessage, self).set(header, str(value))
        return self

    def add(self, h, value):
        if isinstance(h, basestring) and len(h):
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

    def setMessage(self, data):
        if isinstance(data, basestring) and len(data):
            self.__message = data
        return self

    def setBody(self, data):
        if isinstance(data, basestring) and len(data):
            self.__body = data
        return self

    def setversion(self, version):
        if isinstance(version, basestring) and version:
            if version in ("1.0", 1, 1.0 ):
                self.__version = "1.0"
            if version in ("1.1", 1.1 ):
                self.__version = "1.1"
            elif version in (2, "2.0", "2"):
                self.__version = "2"
        return self

    def reset(self):
        self.__message = None
        self.__body = None
        super(HTTPMessage, self).reset()

class WebData(UtilsCI):

    def __init__(self):
        super(WebData, self).__init__()

    def set(self, header, value):
        if value is None:
            value = ""
        # headers could not be empty: no value - no header
        super(WebData, self).set(header, str(value))
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
        # default is return URL-Encoded POST data
        return self.getURLEncoded()

    def setData(self, data):
        if isinstance(data,  basestring) and len(data):
            self.__data = data

    def reset(self):
        self.__data = ""
        super(POSTData, self).reset()

class WebService(object):
    _scheme = "https" # protected: accessible from derived classes
    _port = 443       # protected: accessible from derived classes

    def __init__(self):
        super(WebService, self).__init__()

    def scheme(self):
        return self._scheme

    def port(self):
        return self._port

    def secure(self, flag = True):
        if isinstance(flag, bool) and not flag:
            self._scheme = "http"
        else:
            self._scheme = "https"
        return self

    def setport(self, port = 0):
        if isinstance(port, int) and port >= 1 and port <= 65535:
            self._port = port
        elif self.scheme() == "https":
            self._port = 443
        else:
            self._port = 80
        return self

class SetupHeadersInterface(object):

    __headers = None

    def __init__(self):
        super(SetupHeadersInterface, self).__init__()
        self.__headers = HTTPMessage()

    # Ability to have WebResource specific headers
    def addheader(self, name, value):
        if isinstance(value, basestring) and value:
            self.__headers[name] = value
        return self

    def __setupheader(self, request, name, value):
        if isinstance(request, WebRequest):
            request[name] = value
        elif isinstance(request, urllib2.Request):
            request.add_header(name, value)

    # populate WebResource specific headers to into request object
    def setupheaders(self, request):
        for h in self.__headers:
            self.__setupheader(request, h, self.__headers[h])
        return self

class WebSite(WebService, SetupHeadersInterface):

    __hostname = None

    def __init__(self, hostname = "localhost"):
        super(WebSite, self).__init__()
        self.sethostname(hostname)

    def geturl(self):
        url = "%s://%s" % ( self._scheme, self.__hostname )
        if self._port in ( 80, 443 ):
            return url
        return "%s:%s" % ( url, self._port )

    def gethost(self):
        return self.__hostname

    # default hostname is "localhost", hostname should be defined for WebService
    def sethostname(self, hostname ):
        if isinstance(hostname, basestring) and hostname:
            hostname = hostname.lower()
            checker = re.compile("^([a-z0-9]+([a-z0-9-]*[a-z0-9])*)((\.[a-z0-9]+([a-z0-9-]*[a-z0-9])*)*(\.([a-z]{2,}|xn--[a-z0-9]{2,})))?$", re.I)
            if checker.match(hostname) is not None:
                self.__hostname = hostname
                # website specific header
                self.addheader("Host", self.__hostname)
                return self
        self.__hostname = "localhost"
        self.addheader("Host", "localhost")
        # localhost could not be secure by default
        self.secure(False)
        return self

class WebResource(WebSite):

    __path = "/"
    __headers = None

    def __init__(self, host = "localhost", path = "/"):
        super(WebResource, self).__init__(host)
        self.setpath(path)
        # each resource could have own set of headers
        self.__headers = HTTPMessage()

    def linkto(self, website):
        if isinstance(website, WebSite):
            self.sethostname(website.gethost())
            if website.scheme() == "http":
                self.secure(False)
            self.setport(website.port())
        else:
            raise TypeError("Inappropriate argument type for website.")
        return self

    def getpath(self):
        return self.__path

    def geturl(self):
        return self.getsite() + self.__path

    def getsite(self):
        return super(WebResource, self).geturl()

    def setpath(self, path):
        if isinstance(path, basestring) and path:
            self.__path = "/" + path.lstrip("/")
        else:
            self.__path = "/"
        return self

    def addcomponent(self, subpath):
        if isinstance(subpath, basestring) and subpath:
            self.__path = self.__path.rstrip("/") + "/" +  subpath.lstrip("/")
        return self

    # Web resource URL parser
    # Expected are:
    # http://domain.tld/resource?parameters#fragment
    # https://domain.tld/resource?parameters#fragment
    # domain.tld/resource?parameters#fragment
    # default path - "/"
    def seturl(self, webresource):
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

            self.sethostname(host)
            self.setpath(path)

            return self
        return None

class WebResourceInterface(object):

    _resource = None

    def __init__(self):
        super(WebResourceInterface, self).__init__()

    def linkto(self, webresource):
        if isinstance(webresource, WebResource):
            self._resource = webresource
        elif isinstance(webresource, basestring) and webresource:
            self._resource = WebResource()
            self._resource.seturl(webresource)
        else:
            raise TypeError("Inappropriate argument type for web resource.")
        return self

    def getres(self):
        return self._resource

    def unlink(self):
        self._resource = None
        return self

    def __del__(self):
        pass

# WebRequest should contain
class WebRequest(HTTPMessage, WebResourceInterface):
    __method = "GET"
    __get = None
    __post = None

    __path = "/"

    def __init__(self):
        super(WebRequest, self).__init__()
        self.__post = POSTData()
        self.__get = WebData()

    def getpath(self):
        # we do not want to add this to path (and therefore duplicate data)
        if self.__get.getRaw():
            return self.__path + "?" + self.__get.getURLEncoded()
        return self.__path

    def getmethod(self):
        return self.__method

    def getparams(self):
        return self.__get

    def getData(self):
        return self.__post

    def setData(self, data):
        self.__post.setData(data)

    def geturl(self):
        return self._resource.getsite() + self.getpath()

    def setmethod(self, meth):
        if isinstance(meth, basestring) and meth:
            if meth.upper() in ( "GET", "POST", "HEAD" ):
                self.__method = meth.upper()
        return self

    def __setmethod(self, request):
        # default methods should not be handled
        if self.__method not in ( "GET", "POST" ):
            if isinstance(request, urllib2.Request):
                request.get_method = lambda : self.__method
        return request

    # update path with get parameters
    def setpath(self, path):
        if isinstance(path, basestring) and path:
            self.__path = "/" + path.lstrip("/")
            self.setMessage("%s %s HTTP/%s" % (self.__method, self.getpath(), self.getVersion()) )
        return self

    def addPOST(self, name, value):
        self.__post[name] = value
        self.setmethod("POST")
        return self

    def addGET(self, name, value):
        self.__get[name] = value
        return self

    def delGET(self, name):
        del self.__get[name]
        return self

    def delPOST(self, name):
        del self.__post[name]
        return self

    def linkto(self, webresource):
        super(WebRequest, self).linkto(webresource)
        self.setpath(self._resource.getpath())
        return self

    def unlink(self):
        super(WebRequest, self).unlink()
        self.setpath("/")
        return self

    # returns urllib2.Request object
    def prepare(self, webresource = None):
        # link request to provided resource if specified
        if webresource:
            self.linkto(webresource)

        # prepare urllib2.Request object
        r = urllib2.Request(self.geturl())

        # propagate headers
        for h in self:
            r.add_header(h, self[h])

        # propagate body from POST data
        self.setBody()
        if self.bodySize():
            r.add_data(self.getBody())

        return self.__setmethod(r)

    def setBody(self):
        # Raw data if set or URL-Encoded data if not
        return super(WebRequest, self).setBody(self.__post.getData())

    # http://www.amazon.com/review/product/B00OO3OZYG?SubscriptionId=AKIAJYAW23VXUFYJ3XCQ&tag=nkawus-20&linkCode=xm2&camp=2025&creative=386001&creativeASIN=B00OO3OZYG
    def seturl(self, url):
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
            if self._resource:
                self._resource.seturl(url)
                # we need relink resource becase linkto operation has custom
                # rules for most web requests objects
                self.linkto(self._resource)
            else:
                self.linkto(url)
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
                self.setMessage("HTTP/%s %s %s" % (self.getVersion(), self.__status, self.__reason))
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
            self.setMessage("HTTP/%s %s %s" % (self.getVersion(), self.__status, httplib.responses[self.__status]))
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
        super(WebClient, self).linkto(webresource)
        # setup cookies
        self.__setCookies()
        # setup opener object to use cookies
        self.__opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.__cookies))
        return self

    # return urllib2 response object if request was successfull
    # return None if fail
    def sendRequest(self, webrequest):
        if not self._resource:
            raise ValueError("Web address is not specified. Use setAddress() to define it.")
        if not isinstance(webrequest, WebRequest):
            raise TypeError("Inappropriate argument type for web request.")

        # setup request headers
        self.setupheaders(webrequest)

        u2request = webrequest.prepare(self._resource)

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

    def setupheaders(self, request):
        # if web resource has own specific headers
        self._resource.setupheaders(request)
        # setup browser specific headers
        return super(WebClient, self).setupheaders(request)

    def getStatus(self):
        return self.__response.getstatus()

    def getResponse(self):
        return self.__response

    def __setCookies(self):
        self.savecookies()
        cookiesfile = COOKIESDIR + "/" + self._resource.gethost() + ".txt"
        self.__cookies = cookielib.LWPCookieJar(cookiesfile)
        if os.path.isfile(cookiesfile):
            self.__cookies.load()

    def setUA(self, value):
        return self.addheader("User-Agent", value)

    def setMTypes(self, value):
        return self.addheader("Accept", value)

    def setConn(self, value = "keep-alive"):
        return self.addheader("Connection", value)

    def setLang(self, value):
        return self.addheader("Accept-Language", value)

    def setEnc(self, value):
        return self.addheader("Accept-Encoding", value)

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
        self.addheader("Upgrade-Insecure-Requests", "1")
        self.addheader("Cache-Control", "no-cache")
        self.addheader("Pragma", "no-cache")

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

        self.request.linkto(self.resource)

        self.ua.setAddress(self.request.getres())
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

    def seturl(self, url):
        if isinstance(url, basestring) and url:
            self.resource.seturl(url)
            self.request.seturl(url)

    def __del__(self):
        pass
