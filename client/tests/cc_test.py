import base64
import pkcs11
import time
from pkcs11 import KeyType, ObjectClass, Mechanism
from OpenSSL import crypto
from pkcs11.constants import Attribute
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA
from Crypto.Signature import PKCS1_v1_5 
from base64 import b64decode 

class CartaoDeCidadao:

    def __init__(self, lib_location = "/usr/lib/libpteidpkcs11.so"):
        """
            Cartao de Cidadao constructor, starts by initialising PKCS#11 library and class variables
        """
        self.lib = pkcs11.lib( lib_location )   # Initialise PKCS#11 library
        self.session = None
        self.label = "CARTAO DE CIDADAO"

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


    def get_private_key(self):
        """
            Gets Signature Private Key form Citizen Card
        """
        return next(self.session.get_objects({Attribute.LABEL : "CITIZEN SIGNATURE KEY"}))

    def get_public_key(self):
        """
            Get Raw PEM Signatura Public Key from Citizen Card Certificate
        """
        sig_certificate = next(self.session.get_objects({Attribute.LABEL: "CITIZEN SIGNATURE CERTIFICATE"}))
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, sig_certificate[Attribute.VALUE])
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
            



# Test code
cc = CartaoDeCidadao()
cc.scan()

clear_text = "Batata"

test = cc.sign(clear_text)
print(cc.verify_signature(test, "Batata"))