#!/usr/bin/python

import re
import urllib2, urllib, httplib, socket
from utils import UtilsCI
import cookielib
import os.path
from StringIO import StringIO
import select
import gzip
from log import LogInterface

# maximum attemps count to send request to server
MAXATTEMPTS = 5
SOCKTIMEOUT = 5

# RFC2616 was replaced by multiple RFCs (7230-7237)

class HTTPMessage(UtilsCI):

    # An HTTP message can be either a request from client to server or a
    # response from server to client.  Syntactically, the two types of message
    # differ only in the start-line, which is either a request-line (for
    # requests) or a status-line (for responses)
    # https://tools.ietf.org/html/rfc7230#section-3.1
    __startLine = None
    __up = True

    # https://tools.ietf.org/html/rfc7230#section-3.3
    __body = None
    __version = "1.1"    # HTTP-version

    def __init__(self):
        super(HTTPMessage,self).__init__()

    def startLine(self):
        return self.__startLine

    def modified(self):
        return not self.__up

    def resetStartLine(self):
        self.__up = False

    def setStartLine(self, data):
        if isinstance(data, basestring) and data:
            self.__startLine = data
            self.__up = True
            return self.__startLine
        return None

    def getBody(self):
        return self.__body

    # return HTTP message body size
    def bodySize(self):
        if isinstance(self.__body, basestring):
            return len(self.__body)
        return 0

    def setBody(self, data):
        if isinstance(data, basestring) and data:
            self.__body = data
            return self.__body
        return None

    # return HTTP version
    def getVersion(self):
        return self.__version

    def setVersion(self, version):
        if not (isinstance(version, basestring) and version):
            if version not in (1, 1.0, 1.1, 2):
                return None

        if version in ("1.0", 1, 1.0):
            version = "1.0"
        elif version in ("2", "2.0", 2):
            version = "2"
        else:
            version = "1.1"

        if version == self.__version:
            return version

        self.__version = version
        self.__up = False

        return self.__version

    # set HTTP header
    def _set(self, header, value):
        # headers could not be empty: no value - no header
        # support integer 0 as wells
        if value or isinstance(value, int):
            return super(HTTPMessage, self)._set(header, str(value))
        return None

    # https://tools.ietf.org/html/rfc7230#section-3.2.2
    # A sender MUST NOT generate multiple header fields with the same field name
    # in a message unless either the entire field value for that header field is
    # defined as a comma-separated list [i.e., #(values)] or the header field is
    # a well-known exception (as noted below).
    # A recipient MAY combine multiple header fields with the same field name
    # into one "field-name: field-value" pair, without changing the semantics of
    # the message, by appending each subsequent field value to the combined
    # field value in order, separated by a comma.  The order in which header
    # fields with the same field name are received is therefore significant to
    # the interpretation of the combined field value; a proxy MUST NOT change
    # the order of these field values when forwarding a message.
    #   Note: In practice, the "Set-Cookie" header field ([RFC6265]) often
    #   appears multiple times in a response message and does not use the list
    #   syntax, violating the above requirements on multiple header fields with
    #   the same name.  Since it cannot be combined into a single field-value,
    #   recipients ought to handle "Set-Cookie" as a special case while
    #   processing header fields.
    def add(self, h, value):
        if isinstance(h, basestring) and h:
            # headers could not be empty: no value - no header
            if value or isinstance(value, int):
                # headers names are case-insensitive
                if h in self:
                    header = self[h]
                    if isinstance(header, list):
                        header += [str(value)]
                    else:
                        header = [header, str(value)]
                    return super(HTTPMessage, self)._set(h, header)
                else:
                    return self._set(h, value)
        return None

    def reset(self):
        self.__startLine = None
        self.__up = True
        self.__body = None
        self.__version = "1.1"
        super(HTTPMessage, self).reset()

# POST or GET key-value parameters
class WebData(UtilsCI):

    def __init__(self):
        super(WebData, self).__init__()

    # python None is empty string
    def _set(self, key, value):
        if value is None:
            value = ""
        return super(WebData, self)._set(key, str(value))

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
            return self.__data
        return None

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
        return self.__scheme

    def setPort(self, port = 443):
        if isinstance(port, int) and port >= 1 and port <= 65535:
            self.__port = port
        elif self.scheme() == "http":
            self.__port = 80
        else:
            self.__port = 443
        return self.__port

# interface which provide ability to store HTTP headers and propagate them into
# WEB request objects
class SetupHeadersInterface(object):

    __headers = None

    def __init__(self):
        super(SetupHeadersInterface, self).__init__()
        self.__headers = HTTPMessage()

    def setHeader(self, name, value):
        return self.__headers._set(name, value)

    # Ability to have WebResource specific headers
    def addHeader(self, name, value):
        return self.__headers.add(name, value)

    # setup headers into Request object
    def __setupHeader(self, request, name, value):
        # WebRequest is child of HTTPMessage
        if isinstance(request, WebRequest):
            request[name] = value
            return value
        elif isinstance(request, urllib2.Request):
            if isinstance(value, list):
                value = ",".join(value)
            request.add_header(name, value)
            return value
        return None

    def setupHeaders(self, request):
        for h in self.__headers:
            self.__setupHeader(request, h, self.__headers[h])
        return request

# WebSite is object which responsible for connection to specific host/site
class WebSite(WebService, SetupHeadersInterface):

    # The host subcomponent of authority is identified by an IP literal
    # encapsulated within square brackets, an IPv4 address in dotted-decimal
    # form, or a registered name.  The host subcomponent is case-insensitive.
    # https://tools.ietf.org/html/rfc3986#section-3.2.2
    __hostname = None

    def __init__(self, hostname):
        super(WebSite, self).__init__()
        self.setHost(hostname)

    def host(self):
        return self.__hostname

    def url(self):
        if self.__hostname:
            url = "%s://%s" % (self.scheme(), self.__hostname)
            if self.port() in (80, 443):
                return url
            return "%s:%s" % (url, self.port())
        return None

    # hostname should be defined for WebService
    # supported only registered names (no IPv4 or IPv6)
    def setHost(self, hostname):
        if isinstance(hostname, basestring) and hostname:
            hostname = hostname.lower()
            checker = re.compile(r'^([a-z0-9]+([a-z0-9-]*[a-z0-9])*)((.[a-z0-9]+([a-z0-9-]*[a-z0-9])*)*(.([a-z]{2,}|xn--[a-z0-9]{2,})))?$', re.I)
            if checker.match(hostname) is not None:
                self.__hostname = hostname
                # website specific header
                self.setHeader("Host", self.__hostname)
                return self.__hostname
        return None

# WebResource is object which responsible for connection to separate URL path on
# Web site
class WebResource(WebSite):

    # The path component contains data, usually organized in hierarchical form,
    # that, along with data in the non-hierarchical query component (Section
    # 3.4), serves to identify a resource within the scope of the URI's scheme
    # and naming authority (if any).  The path is terminated by the first
    # question mark ("?") or number sign ("#") character, or by the end of the
    # URI. (https://tools.ietf.org/html/rfc3986#section-3.3)
    __path = "/"

    def __init__(self, host = None, path = "/"):
        super(WebResource, self).__init__(host)
        self.setPath(path)

    def path(self):
        return self.__path

    def setPath(self, path):
        if isinstance(path, basestring) and path:
            self.__path = "/" + path.lstrip("/")
        else:
            self.__path = "/"
        return self.__path

    # support for linkig WebSite into WebResource
    def linkTo(self, website):
        if not isinstance(website, WebSite):
            raise TypeError("Inappropriate argument type for website.")
        self.setHost(website.host())
        if website.scheme() == "http":
            self.secure(False)
        self.setPort(website.port())
        return self.url()

    # return URL of Web site we connect to (ie https://domain.com)
    def getSiteURL(self):
        return super(WebResource, self).url()

    def addSegment(self, subpath):
        if isinstance(subpath, basestring) and subpath:
            self.__path = self.__path.rstrip("/") + "/" +  subpath.lstrip("/")
            return self.__path
        return None

    # return Web resource URL (ie https://domain.com/some/path)
    def url(self):
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

            host = None
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
            return self.url()
        return None

class WebResourceInterface(object):

    __resource = None

    def __init__(self):
        super(WebResourceInterface, self).__init__()

    def linkTo(self, webresource):
        if isinstance(webresource, WebResource):
            self.__resource = webresource
            return self.__resource
        elif isinstance(webresource, basestring) and webresource:
            self.__resource = WebResource()
            self.__resource.setURL(webresource)
            return self.__resource
        else:
            raise TypeError("Inappropriate argument type for web resource.")

    def resource(self):
        return self.__resource

    def unlink(self):
        self.__resource = None

    def __del__(self):
        pass

# WebRequest should know WebResource to which it will be submitted
class WebRequest(HTTPMessage, WebResourceInterface, LogInterface):
    __method = "GET"
    __get = None
    __post = None

    def __init__(self):
        super(WebRequest, self).__init__()
        self.__post = POSTData()
        self.__get = WebData()

    def __updateRequestLine(self):
        if self.modified():
            self.setStartLine("%s %s HTTP/%s" % (self.__method, self.path(), self.getVersion()))

    def __setMethod(self, request):
        # default methods should not be handled
        if self.__method not in ( "GET", "POST" ):
            if isinstance(request, urllib2.Request):
                request.get_method = lambda : self.__method
        return request

    def startLine(self):
        self.__updateRequestLine()
        return super(WebRequest, self).startLine()

    def getMethod(self):
        return self.__method

    def setMethod(self, meth):
        if not (isinstance(meth, basestring) and meth):
            return None

        meth = meth.upper()

        # update not required
        if meth == self.__method:
            return meth

        # supported methods
        if meth not in ("GET", "POST", "HEAD"):
            return None

        self.__method = meth
        self.resetStartLine()
        return self.__method

    def getParams(self):
        return self.__get

    def getData(self):
        return self.__post

    def setData(self, data):
        data = self.__post.setData(data)
        if data:
            self.setMethod("POST")
        return data

    def path(self):
        path = "/"
        query = self.__get.getURLEncoded()
        if self.resource():
            path = self.resource().path()
        # we do not want to add query into path
        if query:
            return path + "?" + query
        return path

    def setPath(self, path):
        if not self.resource():
            return None

        if path == self.resource().path():
            return path

        self.resource().setPath(path)
        self.resetStartLine()

        return path

    def url(self):
        if self.resource():
            url = self.resource().getSiteURL()
            if url:
                return url + self.path()
        return None

    def addPOST(self, name, value):
        self.__post[name] = value
        self.setMethod("POST")
        return value

    def addGET(self, name, value):
        if value == self.__get[name]:
            return value

        self.__get[name] = value
        self.resetStartLine()

        return value

    def delGET(self, name):
        if self.__get[name] is None:
            return None

        del self.__get[name]
        self.resetStartLine()

    def delPOST(self, name):
        del self.__post[name]

    def linkTo(self, webresource):
        resource = super(WebRequest, self).linkTo(webresource)
        self.resetStartLine()
        return resource

    def unlink(self):
        super(WebRequest, self).unlink()
        self.resetStartLine()

    # returns urllib2.Request object
    def prepare(self, webresource = None):
        # link request to provided resource if specified
        if webresource:
            self.linkTo(webresource)

        url = self.url()
        if not url:
            return None

        # prepare urllib2.Request object
        r = urllib2.Request(url)

        self.debug("URL: %s" % url, "prepare")
        self.debug("request line: %s" % self.startLine())

        # propagate headers
        for h in self:
            r.add_header(h, self[h])
            self.debug("hdr: %s: %s" % (h, self[h]))

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
            return self.url()
        return None

class WebResponse(HTTPMessage, LogInterface):
    __status = None
    __reason = None

    def __init__(self):
        super(WebResponse, self).__init__()

    def __updateStatusLine(self):
        if self.__reason and self.__status and self.modified():
            self.setStartLine("HTTP/%s %s %s" % (self.getVersion(), self.__status, self.__reason))

    def startLine(self):
        self.__updateStatusLine()
        return super(WebResponse, self).startLine()

    def getStatus(self):
        return self.__status

    def getReason(self):
        return self.__reason

    def encoding(self):
        if "Content-Encoding" in self:
            return self["Content-Encoding"]
        return None

    def setReason(self, phrase):
        if not (isinstance(phrase, basestring) and phrase):
            return None

        if self.__reason == phrase:
            return phrase

        self.__reason = phrase
        self.resetStartLine()

        return self.__reason

    def setStatus(self, code):
        # cheack if provided code is number
        try:
            code = int(code)

            if code == self.__status:
                return code

            # https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html
            # https://tools.ietf.org/html/rfc2774.html
            if code >= 100 and code <= 510 and code in httplib.responses:
                self.__status = code
        except TypeError:
            return None
        # update HTTP message for currnt object
        # check if provided code message is known to us
        # at least known to python (https://docs.python.org/2/library/httplib.html)
        if self.__status:
            self.setReason(httplib.responses[self.__status])
            return self.__status

        return None

    def populate(self, response):
        # urllib2 response object is instance of urllib.addinfourl class
        if isinstance(response, urllib.addinfourl):
            self.reset()
            # set Status-Code and Reason-Phrase
            self.setStatus(response.code)
            self.setReason(response.msg)
            self.debug("status line: %s" % self.startLine(), "populate")
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
                        self.debug("hdr: %s: %s" % (n, v))
                        self.add(n, v)
            # check if body also should be get from response object
            try:
                # check if we have anything to read (response  consists method
                # fileno which is bound to original socket fileno method)
                select.select([response], [], [], 0)
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
            return self.startLine()
        return None

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
        if self.resource().host():
            # setup cookies
            self.__setCookies()
            # setup opener object to use cookies
            self.__opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.__cookies))
            return self.resource()
        return None

    # return urllib2 response object if request was successfull
    # return None if fail
    def sendRequest(self, webrequest):
        if not (self.resource() and self.resource().host()):
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
                return self.__response
            except urllib2.HTTPError as r:
                if isinstance(r, urllib.addinfourl):
                    self.__response.populate(r)
                    return self.__response
                attempt += 1
            except (urllib2.URLError, socket.timeout, IOError):
                attempt += 1

        return None

    def setupHeaders(self, request):
        # if web resource has own specific headers
        self.resource().setupHeaders(request)
        # setup browser specific headers
        return super(WebClient, self).setupHeaders(request)

    def getStatus(self):
        return self.__response.getStatus()

    def getResponse(self):
        return self.__response

    def saveCookies(self):
        if isinstance(self.__cookies, cookielib.CookieJar):
            self.__cookies.save()
            return self.__cookies
        return None

    def __setCookies(self):
        if self.resource().host():
            self.saveCookies()
            cookiesfile = COOKIESDIR + "/" + self.resource().host() + ".txt"
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

    def __del__(self):
        self.saveCookies()

class GoogleChrome(WebClient):

    def __init__(self):
        super(GoogleChrome, self).__init__()
        # Common headers
        self.setUA("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")
        self.setMTypes("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        self.setConn()
        self.setLang("en-US,en;q=0.9")
        self.setEnc("gzip, deflate, br")
        # Google Chrome specific
        self.addHeader("Upgrade-Insecure-Requests", "1")
        self.addHeader("Cache-Control", "no-cache")
        self.addHeader("Pragma", "no-cache")

class GoogleChromeWindows(GoogleChrome):

    def __init__(self):
        super(GoogleChromeWindows, self).__init__()
        # Common headers
        self.setUA("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36")

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

        # check if resouce was properly initialized
        if not self.request.url():
            return None

        self.ua.setAddress(self.request.resource())
        self.ua.sendRequest(self.request)

        resp = self.ua.getResponse()

        # if request was failed, status is not set
        if not resp.getStatus():
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
