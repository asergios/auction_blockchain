import pkcs11
import time
from pkcs11 import KeyType, ObjectClass
from pkcs11.util.rsa import encode_rsa_public_key
from Crypto.PublicKey import RSA

class cartao_de_cidadao:

    def __init__(self, lib_location = "/usr/lib/libpteidpkcs11.so"):
        '''
            Cartao de Cidadao constructor, starts by initialising PKCS#11 library and class variables
        '''
        self.lib = pkcs11.lib( lib_location )   # Initialise PKCS#11 library
        self.session = None
        self.label = "CARTAO DE CIDADAO"

    def scan(self):
        '''
            Scans for a Card Reader with a Card present
        '''
        
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
                self.session = token.open(user_pin="4156", rw=True)
            except:
                print( "Error reading Smart Card. Please make sure you inserted a valid Cartao de Cidadao."  )
                quit()

        else:
            print("Card Reader not found!")
            quit()

        obj = self.session.get_key(label="CITIZEN SIGNATURE CERTIFICATE")
        
        for i in self.session.get_objects():
            print(i)

        #print(next(self.session.get_objects()))
        #key = RSA.importKey(encode_rsa_public_key(obj))
        #print(key)


cc = cartao_de_cidadao()
cc.scan()
