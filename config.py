#!/usr/bin/python
# -*- coding: utf-8 -*-

import os.path
import re
from utils import Utils, BaseUtils
import ConfigParser
from chiffrierung import DEFAULT_KEY_SIZE
from parsers import Parser, YAMLParser

# emulate ConfigParser standard class interface (partially)
# ConfigFileParser is interface because method loads() is not overridden
class ConfigFileParser(Parser):

    __sections = None
    __defaults = None

    def __init__(self):
        super(ConfigFileParser, self).__init__()
        self.reset()

    def _set(self, key, value):
        if isinstance(value, dict):
            if not self.has_section(key):
                self.__sections += [key]
        else:
            # hope it is not bad idea to keep it not uniq :)
            self.__defaults += [(key, value)]
        return super(ConfigFileParser, self)._set(key, value)

    def reset(self):
        self.__sections = []
        self.__defaults = []
        super(ConfigFileParser, self).reset()

    # partially match RawConfigParser.read
    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.read
    def read(self, filename):
        self.parse(filename)

    def defaults(self):
        # return shallow copy
        return self.__defaults[:]

    # partially match RawConfigParser.sections
    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.sections
    def sections(self):
        # return shallow copy
        return self.__sections[:]

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.has_section
    def has_section(self, section):
        return section in self.__sections

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.items
    def items(self, section):

        if section is None:
            return self.defaults()

        # no section - not items
        if not self.has_section(section):
            raise ConfigParser.NoSectionError(section)

        # section is dictionary which support shallow copy
        items = self[section].copy()
        return [(s, items[s]) for s in items]

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.remove_section
    def remove_section(self, section):
        if not self.has_section(section):
            raise ConfigParser.NoSectionError(section)

        del self[section]
        self.__sections.remove(section)

        return True

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.add_section
    def add_section(self, section):
        # Add a section named section to the instance. If a section by the given
        # name already exists, DuplicateSectionError is raised
        if self.has_section(section):
            raise ConfigParser.DuplicateSectionError(section)

        if not (isinstance(section, basestring) and section):
            return False

        self[section] = {}

        return True

    # https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.set
    def set(self, section, option, value = None):

        if not (isinstance(option, basestring) and option):
            return False
        # handle default values (section name is None)
        if section is None:
            self[option] = value
            return True
        # If the given section exists, set the given option to the specified
        # value; otherwise raise NoSectionError
        if not self.has_section(section):
            raise ConfigParser.NoSectionError(section)

        self[section][option] = value
        return True

    def write(self, fp):
        self.dump(fp)

# .INI (or .CNF) files support
class Configuration(BaseUtils):

    parser = None
    path = None

    def __init__(self, fname = None):
        super(Configuration, self).__init__()
        self.parser = ConfigParser.ConfigParser()
        if isinstance(fname, basestring):
            self.path = fname
        self.initialize()

    def initialize(self):
        if self.path:
            self.load(self.path)

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
        for section in self:
            # add sections
            if self.parser.has_section(section):
                self.parser.remove_section(section)
            self.parser.add_section(section)
            # set options inside each section
            for option in self[section]:
                self.parser.set(section, option, self[section][option])
        f = self.openfile(fname, 'w')
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

        # this call required before setDomain method use
        self.reset()
        # validate domain
        self.setDomain(domain)

        if not self.__domain:
            raise ValueError("Missing or incorrect domain name")

        super(DomainConfig, self).__init__(fname)

    # parameter provides ability to redefine domain (reinitialize)
    def initialize(self, domain = None):

        super(DomainConfig, self).initialize()

        if domain is None:
            domain = self.__domain

        # configuration file was not provided - try to read default location
        if not self.path:
            self.load(domain + ".cfg")

        # check data loaded and correct
        if self.domain() != domain:
            if self.path:
                # if content from configuration file is not correct (different
                # domain name), than ignore it
                self.reset()
            self.setDomain(domain)

        # on this point configuration file must be defined
        if not self.path:
            self.path = domain + ".cfg"

    def save(self):
        super(DomainConfig, self).save(self.path)

    def setDomain(self, domain, p = "domain"):
        if p == "domain":
            # section "main", option "domain"
            # check domain name validity (simple check - no punicode)
            r = re.compile(r'^([a-z0-9]+(-[a-z0-9]+)*.)+[a-z]{2,}$', re.I)
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
            e = re.compile(r'^[a-z0-9_.-]+@([a-z0-9]+(-[a-z0-9]+)*.)+[a-z]{2,}$', re.I)
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

class YAMLConfig(ConfigFileParser, YAMLParser):

    def __init__(self):
        super(YAMLConfig, self).__init__()

class YAMLDomainConfig(DomainConfig):

    def __init__(self, domain, fname = None):
        super(YAMLDomainConfig, self).__init__(domain, fname)

    def initialize(self, domain = None):
        self.parser = YAMLConfig()
        super(YAMLDomainConfig, self).initialize(domain)
