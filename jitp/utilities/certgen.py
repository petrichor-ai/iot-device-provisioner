import logging
import os

from OpenSSL import crypto, SSL


logging.basicConfig(
    format='%(asctime)s|%(name).10s|%(levelname).5s: %(message)s',
    level=logging.WARNING
)

log = logging.getLogger('certgen')
log.setLevel(logging.DEBUG)




def createKeyPair(type, bits):
    ''' Create a public/private key pair.
    '''
    pKey = crypto.PKey()
    pKey.generate_key(type, bits)
    return pKey


def createCertRequest(pKey, digest='sha256', **subjects):
    ''' Create a certificate request.
    '''
    req = crypto.X509Req()
    subj = req.get_subject()

    for k, v in subjects.items():
        setattr(subj, k, v) if v else None

    req.set_pubkey(pKey)
    req.sign(pKey, digest)
    return req


def createSelfSignedCertificate(key, serial, validityPeriod, digest='sha256', **subjects):
    ''' Create a Self Signed Certificate.
    '''
    notBefore, notAfter = validityPeriod

    cert = crypto.X509()
    subj = cert.get_subject()

    for k, v in subjects.items():
        setattr(subj, k, v) if v else None

    cert.set_version(2)
    cert.set_serial_number(serial)

    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)

    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)

    cert.add_extensions([
        crypto.X509Extension('basicConstraints', True, 'CA:TRUE'),
        crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
    ])

    cert.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=cert),
        crypto.X509Extension("extendedKeyUsage", False, "clientAuth"),
        crypto.X509Extension("keyUsage", False, "digitalSignature"),
    ])

    cert.sign(key, digest=digest)
    return cert


def createSignedCertificate(req, issuerCertKey, serial, validityPeriod, digest='sha256'):
    ''' Create a certificate given a certificate
        request.
    '''
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod

    cert = crypto.X509()
    cert.set_serial_number(serial)

    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())

    cert.sign(issuerKey, digest=digest)
    return cert


def createCertFile(dumpFile, request):
    ''' Generate local .crt/csr/key files.
    '''
    with open(dumpFile, 'wb') as f:

        if any(check in dumpFile for check in ['.crt', '.pem']):
            f.write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, request).decode('utf-8')
            )
            log.info('dumpFile Certificate: {}, dumped successfully.'.format(dumpFile))

        if any(check in dumpFile for check in ['.csr']):
            f.write(
                crypto.dump_certificate_request(crypto.FILETYPE_PEM, request).decode('utf-8')
            )
            log.info('dumpFile Cert Request: {}, dumped successfully.'.format(dumpFile))

        if any(check in dumpFile for check in ['.key']):
            f.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, request).decode('utf-8')
            )
            log.info('dumpFile PrivateKey: {}, dumped successfully.'.format(dumpFile))

        if any(check in dumpFile for check in ['.cert']):
            f.write(request)
            log.info('dumpFile Symantec rootCA: {}, dumped successfully.'.format(dumpFile))


def loadCertFile(rdFile, rdPath):
    ''' Load .crt/csr/key files.
    '''

    loadFile = os.path.join(rdPath, rdFile)
    if not(os.path.exists(loadFile)):
        log.error('loadFile: {}, file not found'.format(loadFile))
    else:
        log.info('loadFile: {}, file found.'.format(loadFile))

    with open(loadFile, 'rb') as f:
        raw = f.read()

        if any(check in loadFile for check in ['.crt', '.pem']):
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, raw)
            log.info('loadFile Certificate: {}, loaded successfully.'.format(loadFile))
            return cert

        if any(check in loadFile for check in ['.key']):
            pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, raw)
            log.info('loadFile Privatekey: {}, loaded successfully.'.format(loadFile))
            return pkey
