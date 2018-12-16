import os
import logging
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA
from Crypto.Signature import PKCS1_v1_5

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('CM')
logger.setLevel(logging.DEBUG)

'''
NOT FULLY TESTED, BE CAREFUL
'''

class CertManager:

    def __init__(self, cert = None, priv_key = None):

        if cert:
            if (cert.startswith( b'-----BEGIN CERTIFICATE-----' )):
                self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                raw = crypto.dump_publickey(crypto.FILETYPE_PEM, self.cert.get_pubkey())
            else:
                self.cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                raw = crypto.dump_publickey(crypto.FILETYPE_ASN1, self.cert.get_pubkey())

            rsakey = RSA.importKey(raw)
            self.pub_key = PKCS1_v1_5.new(rsakey)

        if priv_key:
            rsakey = RSA.importKey(priv_key)
            self.priv_key = PKCS1_v1_5.new(rsakey)

    def sign(self, data, priv_key = None):
        """
            Signing data with Signature Private Key
        """

        private_key = priv_key
        if not priv_key:
            if not self.priv_key:
                logger.error("No private key given")
                return
            private_key = self.priv_key

        h = SHA.new(data)
        return private_key.sign( h )

    def verify_signature(self, signature, data, pub_key = None):
        """
            Validate signature for certain data
        """

        public_key = pub_key
        if not pub_key:
            if not self.pub_key:
                logger.error("No public key given")
                return False
            public_key = self.pub_key

        digest = SHA.new()
        digest.update(data)

        return public_key.verify(digest, signature)

    def verify_certificate(self, cert = None):
        """
           Validated certificate via chain of trust
        """

        certificate = cert
        if not cert:
            if not self.cert:
                logger.error("No certificate given")
                return False
            certificate = self.cert

        store = crypto.X509Store()

        for filename in os.listdir('src/common/certmanager/certs'):
            f = open('src/common/certmanager/certs/' + filename, 'rb')
            cert_text = f.read()
            try:
                # PEM FORMAT
                if (cert_text.startswith( b'-----BEGIN CERTIFICATE-----' )):
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_text)
                # ASN1 FORMAT
                else:
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_text)

                store.add_cert(cert)
            except Exception as e:
                logger.error("Unable to read certificate: %s", filename)
                continue

        store_ctx = crypto.X509StoreContext(store, certificate)

        result = store_ctx.verify_certificate()

        return True if not result else False
