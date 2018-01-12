## Briefly: how to request certificate from Lets Encrypt

* registration: `./app.py -d bsys.domain.tld -m ssladmin@domain.tld`
* authorization request: `./app.py -d bsys.domain.tld -AUTH`
* get DNS record: `./app.py -d bsys.domain.tld --dns`
* add DNS TXT resource record into domain's zone file
* ensure it is available: `dig txt @ns1.domain.tld _acme-challenge.rpmb.domain.tld`
* authorize: `./app.py -d bsys.domain.tld -DNS`
* certificate request: `./app.py -d bsys.domain.tld -CERT`
* certificate and key are available in the same folder as `./app.py`

    files `bsys.domain.tld.crt` and `bsys.domain.tld.key`
* Lets Encryt intermediate CA is: `data/LetsEncryptAuthorityX3.pem`

## Below is example of certificate request session

Run app.py without option will show main error (domain name is absent) and basic
help

```
[ssladmin@envy letsencrypt]$ ./app.py
Let's Encrypt [10/Jan/2018:17:09:34 +0100] error: Domain name is mandatory
Usage: ./app.py [options] [DOMAIN]

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
```

Try to resolve error - add option `-d` with domain name:

```
[ssladmin@envy letsencrypt]$ ./app.py -d bsys.domain.tld
Let's Encrypt [10/Jan/2018:17:09:49 +0100] error: email address is not correct (mailto: None)
Usage: ./app.py [options] [DOMAIN]

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
```

It will communicate with LetsEncrypt ACME API with request about new domain 
registration (default action). But in turn it will fail because e-mail address
required for registration request (new-reg)

Next command will register domain inside LetsEncrypt

```
[ssladmin@envy letsencrypt]$ ./app.py -d bsys.domain.tld -m ssladmin@domain.tld
LetsEncrypt.send: resource: new-reg
LetsEncrypt.send: status: 201
LetsEncrypt.send: body:
{
  "id": 27347651,
  "key": {
    "kty": "RSA",
    "n": "0oUVXtZMU8w3Zayk3BPk7AZewp6oqEIjqPlYdcg52o9HWYCT4sJ7ykXm_U8Z0uBDEb7CvAL0gBnffMEfEHyrCXoDpSn1QB7y_LFTBbIhvwAsXVwSqQdqb691FDo5RX2PjFrrIg8LbI0vV_vr_fzADabYypT9y8FRucldvMN2l9dyUOxfKILfS7KY2cAA1M9kMgBtUe5TgItfgCXAEoDoC64aLed2LVE82LVO3FjbRAWYNLrDB9xygf0faj-X_PFnHX49kX7P9qVx-u0ekJQ0Uj0I5cNYy6mCpgzuo8X4uUxHKiQKJJha2-rRgo1QjMmrxgZWoO3-0FG-pbHy-IQiNw",
    "e": "AQAB"
  },
  "contact": [
    "mailto:ssladmin@domain.tld"
  ],
  "initialIp": "178.203.187.67",
  "createdAt": "2018-01-10T16:10:08.277637579Z",
  "status": "valid"
}
LetsEncrypt.send: resource: reg
LetsEncrypt.send: status: 202
LetsEncrypt.send: body:
{
  "id": 27347651,
  "key": {
    "kty": "RSA",
    "n": "0oUVXtZMU8w3Zayk3BPk7AZewp6oqEIjqPlYdcg52o9HWYCT4sJ7ykXm_U8Z0uBDEb7CvAL0gBnffMEfEHyrCXoDpSn1QB7y_LFTBbIhvwAsXVwSqQdqb691FDo5RX2PjFrrIg8LbI0vV_vr_fzADabYypT9y8FRucldvMN2l9dyUOxfKILfS7KY2cAA1M9kMgBtUe5TgItfgCXAEoDoC64aLed2LVE82LVO3FjbRAWYNLrDB9xygf0faj-X_PFnHX49kX7P9qVx-u0ekJQ0Uj0I5cNYy6mCpgzuo8X4uUxHKiQKJJha2-rRgo1QjMmrxgZWoO3-0FG-pbHy-IQiNw",
    "e": "AQAB"
  },
  "contact": [
    "mailto:ssladmin@domain.tld"
  ],
  "agreement": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
  "initialIp": "178.203.187.67",
  "createdAt": "2018-01-10T16:10:08Z",
  "status": "valid"
}
```

We've received registration object with status 'valid' (for more detail about
ACME API read their documentation)

Next step is to request authorization object (new-authz) with all available ACME
challanges:

```
[ssladmin@envy letsencrypt]$ ./app.py -d bsys.domain.tld -AUTH
LetsEncrypt.send: resource: new-authz
LetsEncrypt.send: status: 201
LetsEncrypt.send: body:
{
  "identifier": {
    "type": "dns",
    "value": "bsys.domain.tld"
  },
  "status": "pending",
  "expires": "2018-01-17T16:32:16.054270088Z",
  "challenges": [
    {
      "type": "dns-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
      "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo"
    },
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339022",
      "token": "uLPLrdELg1WY0P-uUxzv6IYRV19l9gWjPsT6w4OzgTA"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ]
  ]
}
LetsEncrypt.send: resource: authz
LetsEncrypt.send: status: 200
LetsEncrypt.send: body:
{
  "identifier": {
    "type": "dns",
    "value": "bsys.domain.tld"
  },
  "status": "pending",
  "expires": "2018-01-17T16:32:16Z",
  "challenges": [
    {
      "type": "dns-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
      "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo"
    },
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339022",
      "token": "uLPLrdELg1WY0P-uUxzv6IYRV19l9gWjPsT6w4OzgTA"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ]
  ]
}
```

We've received 2 available ACME challenges - `http-01` and `dns-01`

Our (my :) ) target is DNS ACME challenge. There are tons of HTTP and TLS based
automation tools over internet but they do not allow to request certificate for 
internal company resources.

Next is to generate DNS challenge resource record:

```
[ssladmin@envy letsencrypt]$ ./app.py -d bsys.domain.tld --dns
LetsEncrypt.send: resource: authz
LetsEncrypt.send: status: 200
LetsEncrypt.send: body:
{
  "identifier": {
    "type": "dns",
    "value": "bsys.domain.tld"
  },
  "status": "pending",
  "expires": "2018-01-17T16:32:16Z",
  "challenges": [
    {
      "type": "dns-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
      "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo"
    },
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339022",
      "token": "uLPLrdELg1WY0P-uUxzv6IYRV19l9gWjPsT6w4OzgTA"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ]
  ]
}
_acme-challenge.bsys.domain.tld.	IN TXT	D9dIMId4QkXi1IBPBD4qkcIR1TmvfNbbtSRYznOoCY4
```

Next step is pretty manual (but of course could be automated on our platform) -
is to add TXT record  

```
_acme-challenge.bsys.domain.tld.	IN TXT	D9dIMId4QkXi1IBPBD4qkcIR1TmvfNbbtSRYznOoCY4
```

into DNS zone `domain.tld` (OTRS-55286)

Whait until record is available:

```
[ssladmin@media ~]$ dig txt @ns1.domain.tld _acme-challenge.bsys.domain.tld +short
"D9dIMId4QkXi1IBPBD4qkcIR1TmvfNbbtSRYznOoCY4"
```

Authorize on Lets Encrypt:

```
[ssladmin@envy letsencrypt]$ ./app.py -d bsys.domain.tld -DNS
LetsEncrypt.send: resource: authz
LetsEncrypt.send: status: 200
LetsEncrypt.send: body:
{
  "identifier": {
    "type": "dns",
    "value": "bsys.domain.tld"
  },
  "status": "pending",
  "expires": "2018-01-17T16:32:16Z",
  "challenges": [
    {
      "type": "dns-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
      "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo"
    },
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339022",
      "token": "uLPLrdELg1WY0P-uUxzv6IYRV19l9gWjPsT6w4OzgTA"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ]
  ]
}
LetsEncrypt.send: resource: challenge
LetsEncrypt.send: status: 202
LetsEncrypt.send: body:
{
  "type": "dns-01",
  "status": "pending",
  "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
  "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo",
  "keyAuthorization": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo.fHkwPwINjud5o2Ugon7THtUO72i4qIRx5cdrXBrrjNY"
}
```

Check authorization status:

```
LetsEncrypt.send: resource: authz
LetsEncrypt.send: status: 200
LetsEncrypt.send: body:
{
  "identifier": {
    "type": "dns",
    "value": "bsys.domain.tld"
  },
  "status": "valid",
  "expires": "2018-02-09T17:19:51Z",
  "challenges": [
    {
      "type": "dns-01",
      "status": "valid",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
      "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo",
      "keyAuthorization": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo.fHkwPwINjud5o2Ugon7THtUO72i4qIRx5cdrXBrrjNY",
      "validationRecord": [
        {
          "Authorities": [
            "domain.tld.\t1200\tIN\tNS\tns1.domain.tld.",
            "domain.tld.\t1200\tIN\tNS\tns4.domain.tld.",
            "domain.tld.\t1200\tIN\tNS\tns3.domain.tld.",
            "domain.tld.\t1200\tIN\tNS\tns2.domain.tld."
          ],
          "hostname": "bsys.domain.tld",
          "port": "",
          "addressesResolved": [],
          "addressUsed": "",
          "addressesTried": []
        }
      ]
    },
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339022",
      "token": "uLPLrdELg1WY0P-uUxzv6IYRV19l9gWjPsT6w4OzgTA"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ]
  ]
}
```

Notice that dns-01 challenge is valid

Request certificate from Lets Encrypt:

```
[ssladmin@envy letsencrypt]$ ./app.py -d bsys.domain.tld -CERT
LetsEncrypt.send: resource: authz
LetsEncrypt.send: status: 200
LetsEncrypt.send: body:
{
  "identifier": {
    "type": "dns",
    "value": "bsys.domain.tld"
  },
  "status": "valid",
  "expires": "2018-02-09T17:19:51Z",
  "challenges": [
    {
      "type": "dns-01",
      "status": "valid",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339021",
      "token": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo",
      "keyAuthorization": "iSjMf4gng5qhVqurmqLScOyWXOzDUuUeGyyMTUKqhZo.fHkwPwINjud5o2Ugon7THtUO72i4qIRx5cdrXBrrjNY",
      "validationRecord": [
        {
          "Authorities": [
            "domain.tld.\t1200\tIN\tNS\tns1.domain.tld.",
            "domain.tld.\t1200\tIN\tNS\tns4.domain.tld.",
            "domain.tld.\t1200\tIN\tNS\tns3.domain.tld.",
            "domain.tld.\t1200\tIN\tNS\tns2.domain.tld."
          ],
          "hostname": "bsys.domain.tld",
          "port": "",
          "addressesResolved": [],
          "addressUsed": "",
          "addressesTried": []
        }
      ]
    },
    {
      "type": "http-01",
      "status": "pending",
      "uri": "https://acme-v01.api.letsencrypt.org/acme/challenge/h0WT6A4_mfOU-E1cJmJhU_jHVxL94c0zKS2bVw08ahY/3047339022",
      "token": "uLPLrdELg1WY0P-uUxzv6IYRV19l9gWjPsT6w4OzgTA"
    }
  ],
  "combinations": [
    [
      0
    ],
    [
      1
    ]
  ]
}
```

Get it:

```
[ssladmin@envy letsencrypt]$ ls -al  bsys.domain.tld.crt bsys.domain.tld.key
-rw-rw-r--. 1 ssladmin ssladmin 1809 Jan 10 18:22 bsys.domain.tld.crt
-rw-rw-r--. 1 ssladmin ssladmin 1708 Jan 10 18:22 bsys.domain.tld.key
[ssladmin@envy letsencrypt]$ cat bsys.domain.tld.crt data/LetsEncryptAuthorityX3.pem 
-----BEGIN CERTIFICATE-----
...
...
...
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
```

Enjoy!
