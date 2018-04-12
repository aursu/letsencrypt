#!/usr/bin/python
# -*- coding: utf-8 -*-

import os.path
import re
from utils import BaseUtils
import ConfigParser
from chiffrierung import DEFAULT_KEY_SIZE
from parsers import Parser

# emulate ConfigParser standard class interface (partially)
# ConfigFileParser is interface because method loads() is not overridden
class ConfigFileParser(Parser):

    __sections = None
    __defaults = None

    def __init__(self):
        super(Parser, self).__init__()
        self.reset()

    # method setup() is in use by method parse() to setup already parsed and
    # validated data into self object
    # method setup() provided by class Utils
    # method parse() provided by class Parser
    def setup(self, data):
        if isinstance(data, dict) or isinstance(data, Utils):
            self.reset()
            for s in data:
                if isinstance(data[s], dict):
                    self.__sections += [s]
                else:
                    self.__defaults += [(s, data[s])]
                self.set(s, data[s])
            return data
        return None

    def reset(self):
        self.__sections = []
        self.__defaults = []
        super(ConfigFileParser, self).reset()

    # partially match RawConfigParser.read
    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.read
    def read(self, filename):
        self.parse(filename)

    # partially match RawConfigParser.sections
    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.sections
    def sections(self):
        return self.__sections

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.has_section
    def has_section(self, section):
        return section in self.__sections

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.items
    def items(self, section):
        # basic validation
        if not (isinstance(section, basestring) and section and self.valid()):
            return None

        # no section - not items
        if not self.has_section(section):
            return None

        return [(s, items[s]) for s in self[section]]

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.remove_section
    def remove_section(self, section):
        if not self.has_section(section):
            return False

        del self[section]
        self.__sections.remove(section)

        return True

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.add_section
    def add_section(self, section):
        if self.has_section(section):
            return False

        self[section] = {}
        self.__sections += [section]

        return True

# .INI (or .CNF) files support
class Configuration(BaseUtils):

    parser = None
    path = None

    def __init__(self, fname = None):
        super(Configuration, self).__init__()
        self.parser = ConfigParser.ConfigParser()
        if isinstance(fname, basestring):
            self.path = fname
            self.load(fname)

    # read configuration file "fname" and load its content into self object
    def load(self, fname):
        self.reset()
        if isinstance(fname, basestring) and os.path.isfile(fname):
            try:
                self.parser.read(fname)
                for s in self.parser.sections():
                    self[s] = dict(self.parser.items(s))
                return len(self)
            except ConfigParser.MissingSectionHeaderError:
                # wrong syntax of config file rejects whole file
                return 0
        return None

    def setOption(self, section, option, value):
        if not self[section]:
            # empty section
            self[section] = {}
        if value is None:
            value = ""
        self[section][option] = str(value)
        return self[section][option]

    def getOption(self, section, option):
        if self[section] and option in self[section]:
            return self[section][option]
        return None

    # save data to file
    def save(self, fname):
        # fill in parser object
        for s in self:
            # add sections if missed
            if self.parser.has_section(s):
                self.parser.remove_section(s)
            self.parser.add_section(s)
            # set options inside each section
            for o in self[s]:
                self.parser.set(s, o, self[s][o] )
        f = self.openfile(fname, "w")
        if f:
            self.parser.write(f)
            f.close()

    def empty(self):
        return len(self) == 0

class DomainConfig(Configuration):

    __domain = None

    # fname should be provided in case if configuration file stored in separate
    # folder (not CWD)
    def __init__(self, domain, fname = None):

        # this call required before parent constructor call
        self.reset()

        # validate domain
        self.setDomain(domain)
        if not self.__domain:
            raise ValueError("Missing or incorrect domain name")

        super(DomainConfig, self).__init__(fname)
        self.initialize(domain)

    def initialize(self, domain):
        # configuration file consists valid domain configuration
        # or provided file is empty or non-existing
        if not self.path:
            self.load(domain + ".cfg")

        if self.domain() == domain:
            pass
        else:
            if self.path:
                self.reset()
            self.setDomain(domain)
        if not self.path:
            self.path = domain + ".cfg"

    def save(self):
        super(DomainConfig, self).save(self.path)

    def setDomain(self, domain, p = "domain"):
        if p == "domain":
            # section "main", option "domain"
            # check domain name validity (simple check - no punicode)
            r = re.compile("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", re.I)
            if isinstance(domain, basestring) and r.match(domain) is not None:
                self.__domain = domain
                return self.setOption("main", "domain", domain)
        else:
            return self.setOption("main", p, domain)

    # file name should have extension ".key"
    # if provided file name is wrong - we use domain.key in the same directory
    # as configuration file
    def setKey(self, value, p = "key"):
        if p == "key":
            if isinstance(value, basestring) and value:
                value = self.base64urlencode(value)
                return self.setOption("key", p, value)
        else:
            if p == "bits":
                try:
                    value = int(value)
                except TypeError:
                    value = DEFAULT_KEY_SIZE
            return self.setOption("key", p, value)
        return None

    def setContact(self, value, p = "mailto"):
        if p == "mailto":
            # validate e-mail
            e = re.compile("^[a-z0-9_.-]+@([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$", re.I)
            if isinstance(value, basestring) and e.match(value) is not None:
                return self.setOption("contact", "mailto", value)
        else:
            return self.setOption("contact", p, value)
        return None

    def setChallenges(self, value, p = "type"):
        return self.setOption("challenges", p, value)

    def setCertificate(self, value, p = "crt"):
        # value for crt is in base64 form initially
        if p in ("key", "csr"):
            if isinstance(value, basestring) and value:
                value = self.base64urlencode(value)
        return self.setOption("certificate", p, value)

    def challenges(self, p = "type"):
        return self.getOption("challenges", p)

    def domain(self, p = "domain"):
        return self.getOption("main", p)

    def key(self, p = "key"):
        value = self.getOption("key", p)
        if p == "key":
            if isinstance(value, basestring) and value:
                value = self.base64urldecode(value)
        return value

    def contact(self, p = "mailto"):
        return self.getOption("contact", p)

    def certificate(self, p = "crt"):
        value = self.getOption("certificate", p)
        if p in ("crt", "key", "csr"):
            if isinstance(value, basestring) and value:
                value = self.base64urldecode(value)
        return value
