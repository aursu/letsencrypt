#!/usr/bin/python

import xml.etree.ElementTree
import xml.parsers.expat
from utils import BaseUtils
from HTMLParser import HTMLParser
import json
import yaml

class Parser(BaseUtils):

    def __init__(self):
        super(Parser, self).__init__()

    # return response data validation status: True if data is valid
    # should be overridden in child class
    def valid(self, root = None):
        return isinstance(root, dict)

    # parse text and return parsed object
    # should be overridden in child class
    def loads(self, text):
        raise NotImplementedError

    # read and parse data from file handle and return parsed object
    # could be overridden in child class
    def load(self, fileh):
        text = fileh.read()
        return self.loads(text)

    # parse file
    def parse(self, filename):
        tmpfh = self.openfile(filename)
        if tmpfh:
            try:
                root = self.load(tmpfh)
                if self.valid(root):
                    self.setup(root)
                    tmpfh.close()   # close file before return
                    return root
            except ValueError:
                pass
            tmpfh.close()
        return None

    def fromstring(self, text):
        if isinstance(text, basestring) and text:
            try:
                root = self.loads(text)
                if self.valid(root):
                    self.setup(root)
                    return root
            except ValueError:
                pass
        return None

    def dumps(self):
        raise NotImplementedError

    def dump(self, fp):
        text = self.dumps()
        fp.write(text)

class JSONParser(Parser):

    def __init__(self):
        super(JSONParser, self).__init__()

    def load(self, fileh):
        return json.load(fileh)

    def loads(self, text):
        return json.loads(text)

    def valid(self, root = None):
        return (isinstance(root, dict) or isinstance(root, list))

    # to support integer indexes as well (allow us to support Python list
    # for initialization)
    def _set(self, key, value):
        return super(JSONParser, self)._set(str(key), value)

    def setup(self, data):
        if isinstance(data, list):
            data = {str(i): data[i] for i in xrange(len(data))}
        return super(JSONParser, self).setup(data)

    def dumps(self):
        return json.dumps(self._dict(), indent = 2)

    def dump(self, fp):
        return json.dump(self._dict(), fp, indent = 2)

class YAMLParser(Parser):
    """Parser for YAML text and files.
    Requirements:
        package PyYAML must be installed
    Valid input is syntactically correct YAML text or file
    """

    def __init__(self):
        super(YAMLParser, self).__init__()

    def loads(self, text):
        return yaml.load(text)

    def dumps(self):
        return yaml.dump(self._dict(), default_flow_style = False,
                explicit_start = True)

    def dump(self, fp):
        return yaml.dump(self._dict(), fp, default_flow_style = False,
                explicit_start = True)

class XMLParser(BaseUtils):

    __xmlp = None
    __xmltree = None
    _root = None

    def __init__(self):
        super(XMLParser, self).__init__()
        self.reset()

    def getroot(self):
        return self._root

    def reset(self):
        self.__xmltree = xml.etree.ElementTree.ElementTree()
        self.__xmlp = self.__getparser()

    def __getparser(self):
        xmlp = xml.etree.ElementTree.XMLParser()
        # we do not support namespaces
        expatp = xml.parsers.expat.ParserCreate(encoding = None, namespace_separator = None)

        # underscored names are provided for compatibility only
        xmlp.parser = xmlp._parser = expatp
        # callbacks
        expatp.DefaultHandlerExpand = xmlp._default
        expatp.StartElementHandler = xmlp._start
        expatp.EndElementHandler = xmlp._end
        expatp.CharacterDataHandler = xmlp._data
        # optional callbacks
        expatp.CommentHandler = xmlp._comment
        expatp.ProcessingInstructionHandler = xmlp._pi

        # let expat do the buffering, if supported
        try:
            xmlp._parser.buffer_text = 1
        except AttributeError:
            pass

        # use new-style attribute handling, if supported
        try:
            xmlp._parser.ordered_attributes = 1
            xmlp._parser.specified_attributes = 1
            expatp.StartElementHandler = xmlp._start_list
        except AttributeError:
            pass
        return xmlp

    def parse(self, source = None):
        self.__tmpfh = self.openfile(source)
        if self.__tmpfh:
            self.__xmltree.parse(source, self.__xmlp)
            self._root = self.__xmltree.getroot()
            self.__tmpfh.close()
        return self._root

    def fromstring(self, text):
        if isinstance(text, basestring) and text:
            self.__xmlp.feed(text)
            self._root = self.__xmlp.close()
        return self._root


# we want to parse only particular HTML tags inside text
class FastParser(HTMLParser):

    __starttag = None
    # we are looking for empty tag by default like <link ... />
    __endtag = ">"

    __flany = None
    __flall = None
    __contentfilter = False
    __tagfilter = False

    def filteror(self, filt):
        if isinstance(filt, basestring) and len(filt):
            self.__flany += [ filt ]

    def filterand(self, filt):
        if isinstance(filt, basestring) and len(filt):
            self.__flall += [ filt ]

    # remove any filtering during parsing
    def nofilter(self):
        self.__flany = []
        self.__flall = []
        self.contentfilter(False)
        self.tagfilter(False)

    def tagfilter(self, flag ):
        if isinstance(flag, bool):
            self.__tagfilter = flag

    def contentfilter(self, flag ):
        if isinstance(flag, bool):
            self.__contentfilter = flag

    # check if string "data" could be accepted by filters
    def accept(self, data):
        # "any of" filters has higher priority
        # if any filter matches - accept for processing
        # otherwise - NOT
        if len(self.__flany):
            for f in self.__flany:
                if f in data:
                    return True
            return False
        # if any of filters does not match - reject string
        for f in self.__flall:
            if f not in data:
                return False
        return True

    # data should start with HTML tag open character("<"), otherwise - reject
    # whole tag content will be checked by accept method
    def accepttag(self, data):
        if data[0] == "<":
            posend = data.find(">")
            if posend > 0:
                return self.accept(data[0:posend])
        return False

    def __init__(self, tag = None, etag = None ):
        HTMLParser.__init__(self)
        if isinstance(tag, basestring):
            tag = tag.strip("</>")
            self.__starttag = "<" + tag
            # check if this is tag with closing element like <script ... > ... </script>
            if isinstance(etag, basestring) and len(etag):
                if etag not in (">", "/>"):
                    self.__endtag = "</" + tag + ">"
        self.nofilter()

    # return position of ending tag
    # tagpos is exact position of starting tag
    # return -1 if nothing found
    def wholetag(self, data, tagpos):
        if data.find(self.tag(), tagpos) == tagpos:
            taglen = len(self.tag())
            etaglen = len(self.etag())
            counter = 1
            cursor = tagpos + taglen
            while counter > 0:
                etagpos = data.find(self.etag(), cursor)
                if etagpos >= cursor:
                    while self.tag() in data[cursor:etagpos]:
                        counter += 1
                        cursor = data.find(self.tag(), cursor) + taglen
                    counter -= 1
                    cursor = etagpos + etaglen
                else:
                    return -1
            return cursor
        return -1

    def feed(self, data):
        if isinstance(data, basestring) and data:
            # print "feed: %s; tag: %s" % ( len(data), self.tag() )
            if self.tag() is None:
                # print "self.tag() is None"
                HTMLParser.feed(self, data)
                return
            taglen = len(self.tag())
            tagpos = data.find( self.tag(), 0)
            while tagpos >= 0:
                etagend = self.wholetag(data, tagpos)
                if etagend > 0:
                    fddata = data[tagpos:etagend]
                    if self.__tagfilter:
                        if self.accepttag(fddata):
                            self.reset()
                            HTMLParser.feed(self, fddata)
                    elif self.__contentfilter:
                        if self.accept(fddata):
                            self.reset()
                            HTMLParser.feed(self, fddata)
                    else:
                        self.reset()
                        HTMLParser.feed(self, fddata)
                    tagpos = data.find(self.tag(), tagpos + taglen)
                else:
                    break

    # tag which we are looking for
    def tag(self):
        return self.__starttag

    # end tag
    def etag(self):
        return self.__endtag

class SimpleHTMLParser(FastParser):

    __tag = None
    __params = None
    __datas = None	# strings array
    __data = None

    def __init__(self, tag = None, etag = None):
        FastParser.__init__(self, tag, etag)
        self.__params = {}
        self.__datas = []

    def settag(self, tag = None):
        if isinstance(tag, basestring):
            self.__tag = tag
        else:
            self.__tag = None
        return self.__tag

    def gettag(self):
        return self.__tag

    def setp(self, attrs = None):
        if attrs and isinstance(attrs, list):
            try:
                self.__params = dict(attrs)
            except TypeError:
                self.__params = {}
        else:
            self.__params = {}
        return self.__params

    def getp(self, pname = None):
        if pname is None:
            return self.__params
        if pname and isinstance(pname, str) and pname in self.__params:
            return str(self.__params[pname])
        return None

    def id(self):
        return self.getp("id")

    def cls(self):
        return self.getp("class")

    def href(self):
        return self.getp("href")

    def pushdata(self, data):
        if isinstance(data, basestring):
            self.__datas += [ data ]
            return data
        return None

    def topdata(self):
        if len(self.__datas):
            return self.__datas[-1]
        return None

    def popdata(self):
        if len(self.__datas):
            return self.__datas.pop()
        return None

    def getdata(self):
        return self.__data

    def alldata(self):
        return self.__datas

    def setdata(self, data = None):
        if data is None:
            self.__data = None
        if isinstance(data, basestring):
            self.__data = data
        return self.__data

    def adddata(self, data):
        self.setdata(data)
        return self.pushdata(data)

    def deldata(self):
        self.__data = None
        self.popdata()

    def datareset(self):
        self.__data = None
        self.__datas = []

    def handle_starttag(self, tag, attrs):
        self.settag(tag)
        self.setp(attrs)
        # as this is start tag - reset current data value
        self.setdata(None)

    def handle_endtag(self, tag):
        self.setdata(None)
        self.settag(None)
        self.setp(None)

    def handle_data(self, data):
        self.adddata(data)

    def _isclass(self, cname):
        s = self.cls()
        if s and cname in s:
            if cname == s or " " + cname + " " in s or s.find(cname + " ") == 0:
                return True
            else:
                return s[-(len(cname) + 1):] == " " + cname
        return False
