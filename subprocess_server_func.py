# -*- coding: utf-8 -*-

# MDA Network Project
# Ring decentralized P2P network for secure instance-messaging
# By Amr Abdelnaser C&E Engineer, Qatar
# Begin in 31/12/2015 04:23 PM

# This file contain the NodeServer - ( Server-side subprocess functions )

from Crypto.PublicKey import RSA
from Crypto.Util import randpool
from Crypto.Cipher import PKCS1_OAEP


import os, sys
import json
import base64
import time

class subcrypto:

    def __init__(self):
            self.RSAKey = None

    def generateRSAkey(self):

            #generate the RSA key ( for the AES key )
            blah = randpool.RandomPool()
            self.RSAKey = RSA.generate(1024, blah.get_bytes)

            RSAPubKey = self.RSAKey.publickey()
            pup = self.RSAKey.exportKey(format='PEM')

            #send the public key over
            race1 = base64.b64encode(pup)
            go = json.dumps(race1)
            #print " sending the public-key", pup
            print go

    def cryptoserver(self):

            from Crypto.Cipher import AES

            rcstring = ''
            while True:
                try:
                    rcstring = raw_input()
                    #rcstring += buf
                except (EOFError):
                    break #end of file reached
            #print "Encrypted msg :: ", rcstring
            sys.stdout.flush()

            #encmessage is the cipher text

            # getting the AES key to decrypt the msg
            # print " Received total message : ", rcstring

            secretkey, encmessage, secretsign, race1 = rcstring.split(':', 3)

            encmsg = base64.b64decode(encmessage)
            seckey = base64.b64decode(secretkey)
            signature = base64.b64decode(secretsign)

            publickey = base64.b64decode(race1)
            pup2 = RSA.importKey(publickey)
            self.RSAKey = pup2
            rsakey = PKCS1_OAEP.new(self.RSAKey)

            # Verifing the msg before decrypt it !
            from Crypto.Signature import PKCS1_PSS
            from Crypto.Hash import SHA256

            h = SHA256.new()
            h.update(encmsg)
            verifier = PKCS1_PSS.new(self.RSAKey)
            if verifier.verify(h, signature):
                iv = encmsg[:16]
                encmsg = encmsg[16:]
                AESkey = rsakey.decrypt(seckey)
                cipher = AES.new(AESkey, AES.MODE_CFB, iv)
                plaintxt = cipher.decrypt(encmsg)
                plaintxt2 = plaintxt.decode("utf8")
                print plaintxt2
                sys.stdout.flush()
            else:
                print "The signature is not authentic."
                sys.stdout.flush()

if __name__ == '__main__':
    sub = subcrypto()
    if sys.argv[1] == '1':
        sub.generateRSAkey()
    elif sys.argv[1] == '2':
        sub.cryptoserver()
