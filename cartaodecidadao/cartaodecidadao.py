import base64
import pkcs11
import time
import os
from pkcs11 import Mechanism
from OpenSSL import crypto
from pkcs11.constants import Attribute
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode

import chardet


class CartaoDeCidadaoLabel:
	SIGNATURE_CERT = "CITIZEN SIGNATURE CERTIFICATE"
	AUTHENTICATION_CERT = "CITIZEN AUTHENTICATION CERTIFICATE"

	SIGNATURE_KEY = "CITIZEN SIGNATURE KEY"
	AUTHENTICATION_KEY = "CITIZEN AUTHENTICATION KEY"

class CartaoDeCidadao:

    label = "CARTAO DE CIDADAO"

    def __init__(self, lib_location = "/usr/local/lib/libpteidpkcs11.so"):
        """
            Cartao de Cidadao constructor, starts by initialising PKCS#11 library and class variables
        """
        self.lib = pkcs11.lib( lib_location )   # Initialise PKCS#11 library
        self.session = None

    def scan(self):
        """
            Scans for a Card Reader with a Card present
        """

        # Checking if there is any Card Reader available
        if ( self.lib.get_slots() != [] ):

            seconds = 20

            # Checking if there is a Card to read on the Card Reader
            while not self.lib.get_slots(True):
                print("Waiting for Cartao de Cidadao to be inserted... ", seconds)
                seconds -= 1
                if not seconds:
                    print("Card not found!")    # TODO: colorize this
                    quit()
                time.sleep(1)

            # Creating session
            try:
                token = self.lib.get_token( token_label = self.label )
                self.session = token.open()
            except:
                print( "Error reading Smart Card. Please make sure you inserted a valid Cartao de Cidadao."  )
                quit()
        else:
            print("Card Reader not found!")
            quit()

    def get_identity(self, certificate = None):
        """
            Returns identity (subject) of certificate on the a tuple with format (Name, Cartao de Cidadao number)
        """
        if not certificate:
            certificate = self.get_certificate()

        subject = certificate.get_subject()
        return (subject.CN, subject.serialNumber[2:-1])

    def get_certificate(self, label = CartaoDeCidadaoLabel.SIGNATURE_CERT):
        """
            Get Certificate From Citizen Card (Returns OpenSSL.crypto.X509 object)
        """
        sig_certificate = next(self.session.get_objects({Attribute.LABEL: label}))
        return crypto.load_certificate(crypto.FILETYPE_ASN1, sig_certificate[Attribute.VALUE])

    def get_certificate_raw(self, label = CartaoDeCidadaoLabel.SIGNATURE_CERT):
        """
            Get Certificate From Citizen Card (Returns raw)
        """
        sig_certificate = next(self.session.get_objects({Attribute.LABEL: label}))
        return sig_certificate[Attribute.VALUE]

    def get_private_key(self, label = CartaoDeCidadaoLabel.SIGNATURE_KEY):
        """
            Gets Signature Private Key form Citizen Card (Returns pkcs11.PrivateKey Object)
        """
        return next(self.session.get_objects({Attribute.LABEL : label}))

    def get_public_key(self):
        """
            Get Raw PEM Signatura Public Key from Citizen Card Certificate
        """
        cert = self.get_certificate()
        public_key_string = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())
        return public_key_string

    def sign(self, data):
        """
            Signing data with Signature Private Key
        """
        private_key = self.get_private_key()
        return private_key.sign( data, mechanism = Mechanism.SHA1_RSA_PKCS )

    def verify_signature(self, signature, data):
        """
            Validate signature for certain data
        """
        public_key = self.get_public_key()

        rsakey = RSA.importKey(public_key)
        signer = PKCS1_v1_5.new(rsakey)

        digest = SHA.new()
        digest.update(data.encode('utf-8'))

        return signer.verify(digest, signature)

    def verify_certificate(self, certificate = None):
        """
           Validated certificate via chain of trust
        """
        if not certificate:
            certificate = self.get_certificate_raw()

        # PEM FORMAT
        if (certificate.startswith( b'-----BEGIN CERTIFICATE-----' )):
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        # ASN1 FORMAT
        else:
            certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)

        store = crypto.X509Store()

        for filename in os.listdir('./cartaodecidadao_certs'):
            f = open('./cartaodecidadao_certs/' + filename, 'rb')
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
