from OpenSSL import crypto, SSL



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

    for key, value in subjects.items():
        setattr(subj, key, value)

    req.set_pubkey(pKey)
    req.sign(pKey, digest)
    return req


def createCertificate(req, issuerCertKey, serial, validityPeriod, digest="sha256", isCA=False):
    ''' Create a certificate given a certificate
        request.
    '''
    issuerCert, issuerKey = issuerCertKey
    notBefore, notAfter = validityPeriod

    cert = crypto.X509()
    cert.set_serial_number(serial)

    cert.add_extensions([
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert)
    ])

    cert.add_extensions([
        crypto.X509Extension("authorityKeyIdentifier", False, "keyid", issuer=cert)
    ])

    cert.add_extensions([
        crypto.X509Extension("basicConstraints", isCA, "CA:{}".format('TRUE, pathlen:0' if isCA else 'FALSE'))
    ])

    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())

    cert.sign(issuerKey, digest=digest)
    return cert


def createCertFile(mkFile, request):
    ''' Generate local .crt/csr/key files.
    '''
    with open(mkFile, 'w') as f:

        if '.crt' in mkFile:
            f.write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, request).decode('utf-8')
            )

        elif '.csr' in mkFile:
            f.write(
                crypto.dump_certificate_request(crypto.FILETYPE_PEM, request).decode('utf-8')
            )

        elif '.key' in mkFile:
            f.write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, request).decode('utf-8')
            )


def loadCertFile(rdFile):
    ''' Load .crt/csr/key files.
    '''
    with open(rdFile, 'r') as f:
        cert = f.read()

        if '.crt' in rdFile:
            return crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        elif '.key' in rdFile:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, cert)
