#!/usr/bin/python
# -*- coding: utf-8 -*-

from utils import BaseUtils
import sys
import os.path

# http://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior
LOGSTAMP = "[%d/%b/%Y:%H:%M:%S %z]"

class LogUtils(BaseUtils):
    __entry = ""
    __entrysep = ""
    __dest = sys.stderr
    __std = True    # standard error output

    def __init__(self, entry = None):
        super(LogUtils, self).__init__()
        self.logentry(entry)

    # set entry (like domain, hostname, user) for which logs entry gathered
    def logentry(self, entry = None ):
        if entry:
            self.__entry = str(entry)
            self.__entrysep = " "

    # return current timestamp in format like [15/Apr/2012:19:29:43 -0400]
    def logstamp(self, stamp = None, formats = LOGSTAMP):
        return self.stamp(stamp, formats)

    # log warning
    # if dupe is True - duplicate message to standard error
    def warn(self, message, dupe = False):
        if isinstance(message, basestring) and message:
            warning = "%s%s%s %s" % (self.__entry, self.__entrysep, self.logstamp(), message)
            print >> self.__dest, warning
            if not self.__std:
                self.__dest.flush()
                if dupe: # duplicate to standard error
                    print >> sys.stderr, warning

    # log error and terminate
    def error(self, message = None, code = -1, dupe = True):
        self.warn(message, dupe)
        sys.exit(code)

    # open/create log file
    def logdest(self, output = None):
        if isinstance(output, basestring) and output:
            self.__dest = self.openfile(output, mode = "a", terminate = True)
            self.__std = False
        else:
            self.__dest = sys.stderr
            self.__std = True

    # this function is part of BaseUtils class but with logging suport
    def openfile(self, path, mode = "r", terminate = False):
        filehandle = super(LogUtils, self).openfile(path, mode, terminate = False)
        if self.errno():
            if terminate:
                self.error(self.strerror(), self.errno())
            else:
                self.warn(self.strerror(), self.errno())
        return filehandle

    def __del__(self):
        if self.__dest and not self.__std:
            self.__dest.close()
