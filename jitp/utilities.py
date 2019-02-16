from OpenSSL import crypto, SSL



def generateCertFiles(mkFile, request):
    """Generate .csr/pem/key files.
    """
    with open(mkFile, 'w') as f:
        if '.crt' in mkFile:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, request))
        elif '.key' in mkFile:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
