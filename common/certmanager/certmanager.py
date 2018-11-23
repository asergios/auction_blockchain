
import os
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA
from Crypto.Signature import PKCS1_v1_5

'''
NOT FULLY TESTED, BE CAREFUL
'''

class CertManager:

    def __init__(self, cert = None, priv_key = None):

        if cert:
            if (cert.startswith( b'-----BEGIN CERTIFICATE-----' )):
                self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                raw = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())
            else:
                self.cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                raw = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())

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
                print("ERROR: no private key given")
                return
            private_key = self.priv_key

        return private_key.sign( data, mechanism = Mechanism.SHA1_RSA_PKCS )

    def verify_signature(self, signature, data, pub_key = None):
        """
            Validate signature for certain data
        """

        public_key = pub_key
        if not pub_key:
            if not self.pub_key:
                print("ERROR: no public key given")
                return
            public_key = self.pub_key

        digest = SHA.new()
        digest.update(data.encode('utf-8'))

        return public_key.verify(digest, signature)

    def verify_certificate(self, cert = None):
        """
           Validated certificate via chain of trust
        """

        certificate = cert
        if not cert:
            if not self.cert:
                print("ERROR: no certificate given")
                return
            certificate = self.cert

        # PEM FORMAT
        if (certificate.startswith( b'-----BEGIN CERTIFICATE-----' )):
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        # ASN1 FORMAT
        else:
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)

        store = crypto.X509Store()

        for filename in os.listdir('./certs'):
            f = open('./certs/' + filename, 'rb')
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
                print("Error reading certificate: ", filename)
                continue

        store_ctx = crypto.X509StoreContext(store, certificate)

        result = store_ctx.verify_certificate()

        return True if not result else False
