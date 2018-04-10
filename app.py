#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import getopt, getpass
import os.path
from log import LogUtils
from letsencrypt import LetsEncrypt

def usage(argv = sys.argv):
    print "Usage: %s [options] [DOMAIN]" % argv[0]
    print """
Options:
    -c, --config CNAME          Configuration file to use
    -d, --domain DOMAIN         Domain name
    -m, --mailto E-MAIL         e-mail address (required for 1st time run)
    -AUTH, --authorization      Request new authorization from ACME server. If
                                current account alredy authorized - it will do
                                nothing unless --force is specified
    --dns                       Request DNS TXT RR to be added for domain
    -DNS, --challenge           Complete the challenges - only if authorization
                                status is "pending" or --force specified
    -CERT, --certificate        Request certificate from ACME server
    -r, --revoke                Revoke certificate specified in configuration
                                file
    -R, --revoke-cert CERT      Revoke certificate provided via command line
    --force                     Proceed Authorization or Certificate Issuance
                                despite the current status
    -h                          show this info and exit
"""
    sys.exit()

# password command line option
PWOPT = "-p"
PWLOPT = "--password"

def clearargpw( args, opts ):
    args = [ a for a in args if a not in opts ]
    # get password from user
    if PWOPT in opts or PWLOPT in opts:
        password = getpass.getpass()
        args = [ PWOPT, password ] + args
    return args

# "p:", ["password="]
def getoptionspw( args, options, long_options = [] ):
    opts = []
    try:
        opts, arest = getopt.gnu_getopt( args, options, long_options )
    except getopt.GetoptError as (msg, opt):
        if opt == PWOPT.lstrip("-") or opt == PWLOPT.lstrip("-"):
            args = clearargpw( args, [ PWOPT, PWLOPT ] )
            opts, arest = getoptionspw( args, options, long_options )
        else:
            print "GetoptError exception: %s" % msg
            usage()
    # check options
    if len(opts) > 0:
        for opt, value in opts:
            # in case if opts are [('-p', '-u'), ('-h', '754'), ('--file', '-c') ]
            if value.find("--") == 0 or value.find("-") == 0:
                if opt not in [ PWOPT, PWLOPT ] and ( options.find(value.lstrip("-")) >= 0 or "%s=" % opt.lstrip("-") in long_options ):
                    print "Option %s requires argument" % opt
                    usage()
                else:
                    args = clearargpw( args, [ opt ] )
                    return getoptionspw(args, options, long_options)
    return ( opts, arest )

def main(argv = sys.argv[1:]):

    log = LogUtils("Let's Encrypt")

    config = None
    domain = None
    mailto = None
    # we will not authorize domain by default
    authz = False
    # authorization and get certificate will be skipped if already done
    force = False
    showdns = False
    challenge = False
    getcert = False
    export = True
    revoke = False
    certpath = None
    opts, argv = getoptionspw(argv, "c:d:m:A:D:C:R:rh", [ "config=", "domain=", "mailto=",
                                                "authorization", "challenge", "dns",
                                                "certificate", "force", "help", "revoke"
                                                "revoke-cert="] )
    for o, v in opts:
        opt = o.lstrip("-")
        if opt in ("h", "help"):
            usage()
        elif opt in ("d", "domain"):
            domain = v
        elif opt in ("m", "mailto"):
            mailto = v
        elif opt in ("c", "config"):
            config = v
        elif ( opt == "A" and v == "UTH" ) or opt == "authorization":
            authz = True
        elif ( opt == "D" and v == "NS" ) or opt == "challenge":
            challenge = True
        elif ( opt == "C" and v == "ERT" ) or opt == "certificate":
            getcert = True
        elif opt == "dns":
            showdns = True
        elif opt == "force":
            force = True
        elif opt in ("r", "R", "revoke", "revoke-cert"):
            revoke = True
            if v:
                certpath = v
        else:
            print "GetoptError exception: option -%s%s not recognized" % (opt, v)
            usage()

    if len(argv) >= 1 and domain is None:
        domain = argv[0]

    if not domain:
        log.warn("error: Domain name is mandatory")
        usage()

    try:
        app = LetsEncrypt(domain, config)
        app.init()
    except ValueError as strerror:
        log.warn("error: %s" % strerror)
        usage()

    appconfig = app.config.path
    if config:
        if config == appconfig:
            log.warn("use provided config: %s" % appconfig)
        else:
            log.warn("provided config could not be used. Please check path (%s)" % congig)
            log.warn("use config: %s" % appconfig)

    # if we are not registered yet (1st run for provided domain)
    if not app.config.domain("reg"):
        # registration
        log.warn("register domain %s" % domain)
        status = app.registerV2(mailto)
        if status is None:
            log.warn("error: email address is not correct (mailto: %s)" % mailto)
            usage()

    if not app.config.contact("agreement"):
        # accept EULA
        app.agreement()

    if authz and (not app.config.domain("authz") or force):
        app.authorization()

    app.checkAuthorization()

    if showdns and app.config.domain("authz"):
        print app.dnsRecord()

    if challenge and app.config.challenges("status") == "pending":
        app.challenge()

    if getcert and app.config.challenges("status") == "valid" and (not app.config.certificate() or force):
        app.certificate()

    if export and app.config.certificate():
        app.saveCert()

    if revoke:
        crt = None
        if certpath and os.path.isfile(certpath):
            crt = open(certpath, "r").read()
        app.revoke(crt)

main()

