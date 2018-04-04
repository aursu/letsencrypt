#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import tzinfo, timedelta, datetime
import time
import os
import os.path
import sys
import base64
import re

MYSQL_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
INTERNET_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# dict object with ability to return None for non-existing keys
# keys are case sensitive
# could return values by accessing object property
# iterable
class Utils(object):
    __defs = None
    __keys = None
    __idx = 0

    def __init__(self):
        super(Utils, self).__init__()
        self.reset()

    def reset(self):
        self.__defs = {}
        self.__keys = []
        self.__idx = 0

    def set(self, key, value):
        if isinstance(key, basestring) and len(key):
            self.__defs[key] = value
            if key not in self.__keys:
                self.__keys += [key]

    def get(self, key):
        if key in self.__keys:
            return self.__defs[key]
        return None

    def __setitem__(self, key, value):
        self.set(key, value)

    def __getitem__(self, key):
        return self.get(key)

    def __getattr__(self, name):
        return self[name]

    def __delitem__(self, key):
        if key in self.__keys:
            i = self.__keys.index(key)
            del self.__keys[i]
            del self.__defs[key]

    def __len__(self):
        return len(self.__keys)

    def __contains__(self, key):
        return key in self.__keys

    # Define iteration
    def __iter__(self):
        self.__idx = 0
        return self

    def next(self):
        if self.__idx == len(self):
            raise StopIteration
        self.__idx += 1
        return self.__keys[self.__idx - 1]

    def ksort(self):
        self.__keys.sort()

    def __del__(self):
        pass

class UtilsCI(object):
    __defs = None
    __keys = None
    __idx = 0

    def __init__(self):
        super(UtilsCI, self).__init__()
        self.reset()

    def reset(self):
        self.__defs = {}
        self.__keys = []
        self.__idx = 0

    def set(self, key, value):
        if isinstance(key, basestring) and len(key):
            if key.lower() not in self.__defs:
                self.__keys += [key]
            self.__defs[key.lower()] = value

    def get(self, key):
        if key.lower() in self.__defs:
            return self.__defs[key.lower()]
        else:
            return None

    def __setitem__(self, key, value):
        self.set(key, value)

    def __getitem__(self, key):
        return self.get(key)

    def __delitem__(self, key):
        if key.lower() in self.__defs:
            del self.__defs[key.lower()]
            for k in self.__keys:
                if k.lower() == key.lower():
                    i = self.__keys.index(k)
                    del self.__keys[i]

    def __len__(self):
        return len(self.__keys)

    def __contains__(self, key):
        return key.lower() in self.__defs

    # Define iteration
    def __iter__(self):
        self.__idx = 0
        return self

    def next(self):
        if self.__idx == len(self):
            raise StopIteration
        self.__idx += 1
        return self.__keys[self.__idx - 1]

    def __del__(self):
        pass

    def ksort(self):
        self.__keys.sort()

# JavaScript array partial emulation (only add/get functionality along with
# iteration, length and string representation)
class JSArray(object):
    __defs = None
    __keys = None
    __i = 0
    def __init__(self):
        super(JSArray, self).__init__()
        self.__defs = {}
        self.__keys = ()
        self.__i = 0
    def set(self, key, value):
        self.__defs[key] = value
        if key not in self.__keys:
            self.__keys += ( key, )
    def get(self, key):
        if key in self.__keys:
            return self.__defs[key]
        else:
            return None
    def __setitem__(self, key, value):
        self.set(key, value)
    def __getitem__(self, key):
        return self.get(key)
    def __len__(self):
        return len(self.__keys)
    # Define iteration
    def __iter__(self):
        self.__i = 0
        return self
    def next(self):
        if self.__i == len(self):
            raise StopIteration
        self.__i += 1
        return self.__keys[self.__i - 1]
    def __repr__(self):
        rpr = "["
        for i in self.__keys:
            rpr += "%s," % self.__defs[i]
        return rpr.rstrip(",") + "]"

class LocalTZ (tzinfo):

    __offset = None
    __DSTOffset = None
    __DSTDiff = None

    def __init__(self):
        # time.timezone - offset of the local non-DST timezone, in seconds west of UTC
        self.__offset = timedelta(seconds = -time.timezone )    # we need adjustment, in minutes east of UTC
        self.__DSTOffset = self.__offset
        # but if DST timezone is defined
        if time.daylight:
            # time.altzone - offset of the local DST timezone, in seconds west of UTC
            self.__DSTOffset = timedelta(seconds = -time.altzone)
        self.__DSTDiff = self.__DSTOffset - self.__offset

    def isDST(self, dt):
        tt = (  dt.year, dt.month, dt.day,
                dt.hour, dt.minute, dt.second,
                dt.weekday(), 0, -1 )   # use -1 as the dst flag if it is unknown
        # get time stamp for provided object
        stamp = time.mktime(tt)
        lc = time.localtime(stamp)
        return lc.tm_isdst == 1 # The dst flag is set to 1 when DST applies to the given time

    def dst(self, dt):
        if self.isDST(dt):
            return self.__DSTDiff
        return timedelta(0)

    def utcoffset(self, dt):
        return self.__offset + self.dst(dt)

    def tzname(self, dt):
        return time.tzname[self.isDST()]

class ErrorHandlingInterface(object):
    __errno = 0 # means no error
    __strerror = None

    def __init__(self):
        super(ErrorHandlingInterface, self).__init__()

    def seterror(self, errno, strerror = None):
        if isinstance(errno, int):
            self.__errno = errno
        if strerror is None:
            strerror = ""
        self.__strerror = str(strerror)

    def errno(self):
        return self.__errno

    def strerror(self):
        return self.__strerror

    def __del__(self):
        pass

class BaseUtils(Utils, ErrorHandlingInterface):

    __tz = None

    def __init__(self):
        super(BaseUtils, self).__init__()
        self.__tz =  LocalTZ()

    # Notes on Implementing base64url Encoding without Padding
    # https://tools.ietf.org/html/rfc7515#appendix-C
    def base64urlencode(self, arg):
        return base64.urlsafe_b64encode(arg).rstrip("=")

    def base64urldecode(self, arg):
        pad = len(arg) % 4
        if pad == 1:
            raise ValueError("Illegal base64url string!")
        s = {
            0: lambda x: x,
            2: lambda x: x + "==",
            3: lambda x: x + "="
        }[pad](arg)
        return base64.urlsafe_b64decode(s)

    # from URL-safe encoded string (with base64)
    def getBytes(self, strtext):
        b64url = re.compile("^[a-zA-Z0-9_-]+$")
        if b64url.match(strtext) is not None:
            rawdata = self.base64urldecode(strtext)
        else:
            rawdata = strtext
        return rawdata

    # timestam in mysql format
    def stamp(self, stamp = None, formats = INTERNET_DATETIME_FORMAT ):
        if stamp is None:
            stamp = int(time.time())
        return datetime.fromtimestamp(stamp, self.__tz).strftime(formats)

    # this function is part of BaseUtils class but with logging suport
    def openfile(self, path, mode = "r", terminate = False ):
        filehandle = None
        if isinstance(path, basestring) and path:
            if os.path.exists(path) and os.path.isfile(path):
                try:
                    filehandle = open(path, mode)
                except IOError as (errno, strerror):
                    self.seterror(errno, "can not open file %s (IOError: %s)" % (path, strerror) )
                    if terminate:
                        sys.exit(errno)
            elif mode in ("a", "w"):
                basedir = os.path.dirname(path)
                if not basedir: # empty string
                    basedir = "."   # current directory
                if os.path.exists(basedir):
                    if os.path.isdir(basedir):
                        filehandle = open(path, "w")
                    else:
                        self.seterror(os.EX_CANTCREAT, "can not create file %s: base directory is not a directory" % path)
                        if terminate:
                            sys.exit(os.EX_CANTCREAT)
                else:
                    try:
                        os.makedirs(basedir)
                        filehandle = open(path, "w")
                    except OSError as ( errno, strerror ):
                        self.seterror(errno, "can not create file %s (OSError: %s)." % ( path, strerror ))
                        if terminate:
                            sys.exit(errno)
        if not filehandle:
            self.seterror(os.EX_CANTCREAT, "file %s could not be created" % path )
            if terminate:
                sys.exit(os.EX_CANTCREAT)
        else:
            self.seterror(0)
        return filehandle

    def __del__(self):
        pass
