# -*- coding: utf-8 -*-
# MDA Network Project
# Ring decentralized P2P network for secure instance-messaging
# By Amr Abdelnaser C&E Engineer, Qatar
# Begin in 14/9/2015 04:23 PM


# This file holds the encryption methods used by MDA Network

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#from Crypto.Util import randpool
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512

import json
import base64


class mda_encryption:
    """
    Secure connections between nodes and Encrypt the data packets and data stored.
    """

    def __init__(self):

        # Crypto info
        self.RSAkey = None
        self.othernode_pup = None
        self.AESkey = None
        self.rcvfile = None

    def pad(self, s):
        """
        Used by encrypt function.
        :param s: packet to be encrypted
        :return: packet ready to encrypt with AES key
        """
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        """
        Encrypt the handled message with AES key.
        :param message: The message need to be encrypted
        :param key: AES key
        :param key_size: optional for future use !
        :return: Encrypted text
        """
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(message)

    @staticmethod
    def decrypt(ciphertext, key):
        """
        Decrypt the handled cipher text with the given AES key.
        :param ciphertext: encrypted text
        :param key: AES key
        :return: Unencrypted text
        """
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def encrypt_f(self, file_name, plaintext, key):
        """
        Encrypt a text and put it into a file
        :param file_name: name of the file
        :param plaintext: text to encrypt
        :param key: AES key
        """
        enc = self.encrypt(plaintext, key)
        out = file_name + ".enc"
        with open(out, 'wb') as fo:
            fo.write(enc)

    def decrypt_f(self, file_name, key):
        """
        Extract a text from file and decrypt it
        :param file_name: name of the file contain cipher text
        :param key: AES key
        :return: Unencrypted text
        """
        file_n = file_name + ".enc"
        with open(file_n, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, key)
        #decmsg = base64.b64decode(dec)
        #print(dec, type(dec))
        return dec.decode()

    @staticmethod
    def generateAESKey():
        """
        generate AES key !!
        :return: AES key
        """
        return Random.new().read(32)

    @staticmethod
    def aesencrypt(plainmsg, RSAKey, AESKey):
        """
        Encrypt a plain text with AES key and encrypt the AES key with RSA key and finally hash the message with SHA
        :param plainmsg: message to be encrypted
        :param RSAKey: RSA key (public key)
        :param AESKey: AES key
        :return: Encodec text ready to send over MDA connection
        """
        try:
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(AESKey, AES.MODE_CFB, iv)
            realmsg = plainmsg
            realmsg2 = realmsg.encode("utf8")
            # print( realmsg2)
            msg = iv + cipher.encrypt(realmsg2)
            #print( RSAKey.publickey)
            signer = PKCS1_PSS.new(RSAKey)
            h = SHA512.new()
            h.update(msg)
            signature = signer.sign(h)

            # encoding
            race3 = base64.b64encode(msg)
            race4 = base64.b64encode(signature)
            # print( "node client side: "," The secretText : ", race4)
            return race3 + ':' + race4
        except:
            raise

    @staticmethod
    def aesdecrypt(msg, AESKey, othernode_pup):
        """
        Verify the message with SHA hashing and then decrypt the received message with AES key.
        :param msg: received encrypted message
        :param AESKey: AES key
        :param othernode_pup: other node RSA public key used in hashing
        :return: plain text
        """
        encmessage, secretsign = msg.split(':', 1)

        encmsg = base64.b64decode(encmessage)
        signature = base64.b64decode(secretsign)

        h = SHA512.new()
        h.update(encmsg)
        verifier = PKCS1_PSS.new(othernode_pup)
        plaintxt2 = ''
        if verifier.verify(h, signature):
            iv = encmsg[:16]
            encmsg = encmsg[16:]
            cipher = AES.new(AESKey, AES.MODE_CFB, iv)
            plaintxt = cipher.decrypt(encmsg)
            plaintxt2 = plaintxt.decode("utf8")
        else:
            print( "The signature is not authentic.")
        return plaintxt2

    @staticmethod
    def generateRSAkey(pa='',op=''):
        """
        Generate the RSA key with password phrase.
        :param pa: password phrase
        :return: encoded rsa key to send and RSA key to use
        """
        # generate the RSA key ( for the AES key )
        #blah = randpool.RandomPool()


        RSAKey = RSA.generate(2048)#, blah.get_bytes)

        RSAPubKey = RSAKey.publickey()
        if pa == '':
            pup = RSAPubKey.exportKey(format='PEM')
        else:
            pup = RSAKey.exportKey(format='PEM', passphrase=pa, pkcs=1)

        # send the public key over
        race1 = base64.b64encode(pup)
        #print(race1, type(race1))
        go = json.dumps(race1.decode())
        # print( " sending the public-key", pup)
        # print( " the encoded key", race1)
        if pa == '':
            gogo = "{}:{}".format(len(go), go)
        else:
            gogo = go

        if op == 'mda1':
            RKey = RSAKey.exportKey(format='PEM', pkcs=1)
            race2 = base64.b64encode(RKey)
            gogo = json.dumps(race2)
        #print( gogo, type(gogo))

        return gogo, RSAKey


    @staticmethod
    def receive_RSAkey(rev):
        length_str, buffer = rev.split(':', 1)
        #print( len(rev))
        length = int(length_str)
        message = buffer[:length]
        race1 = json.loads(message)
        publickey = base64.b64decode(race1)
        pup = RSA.importKey(publickey)
        return  pup, buffer[length:]


    @staticmethod
    def cryptoserver(rcstring, RSAKey, verfingkey):
        """
        Ecryption function used by mdaserver
        :param rcstring: received message
        :param RSAKey: RSA Key
        :param verfingkey: RSA key of the other side to verify the signature.
        :return:
        """

        rsakey = PKCS1_OAEP.new(RSAKey)
        #encmessage is the cipher text
        #race2 = json.loads(rcstring)

        # getting the AES key to decrypt the msg
        # print( " Received total message : ", rcstring)

        secretkey, encmessage, secretsign = rcstring.split(':', 2)

        #secretkey = rcstring.split(':')
        #secretsign = rcstring.split(':')

        encmsg = base64.b64decode(encmessage)
        seckey = base64.b64decode(secretkey)
        signature = base64.b64decode(secretsign)

        # Verifing the msg before decrypt it !

        iv = None
        AESkey = None
        h = SHA512.new()
        h.update(encmsg)
        verifier = PKCS1_PSS.new(verfingkey)
        plaintxt2 = ''
        if verifier.verify(h, signature):
            iv = encmsg[:16]
            encmsg = encmsg[16:]
            AESkey = rsakey.decrypt(seckey)
            cipher = AES.new(AESkey, AES.MODE_CFB, iv)
            plaintxt = cipher.decrypt(encmsg)
            plaintxt2 = plaintxt.decode("utf8")
        else:
            print( "cryptoserver: The signature is not authentic.")

        #sys.exit(0)  # kill the child process
        #print( "AESkey: ", AESkey)

        return plaintxt2, AESkey, iv
