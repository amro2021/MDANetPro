import os
import sys
import base64
from Crypto.Cipher import PKCS1_OAEP



# to check if the file empty (no messages) or not (new messages)
def file_is_empty(path):
    return os.stat(path).st_size==0

in_filename = "test"
in_file = in_filename + ".enc"

dropmsg = base64.b64encode("Hello cryptography world {}".format("!!"))
# write to a file without remove the old messages "w" flush the file before writing in it.
#with open(in_filename, "ab") as myfile:
 #   myfile.write(dropmsg)

# to return to the begin of the file to start reading
#f.seek(0)


# to check if the file is exist or not
'''
Path = ""
File = ""
try:
    if os.stat(Path + File).st_size > 0:
        print "Processing..."
    else:
        print "Empty URL file ... exiting"
        sys.exit()
except OSError:
    print "URL file missing ... exiting"
    sys.exit()

'''
#lock the file until the writer or reader finish then continue
import os, random, struct
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.PublicKey import RSA


#iv = Random.new().read(AES.block_size)



def encrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))
                print "The encrypted file is: ", out_filename


def decrypt_file(key, in_filename, out_filename=None, chunksize=24*1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)
            print "\nThe Decrypted file is: ", out_filename


#encrypt_file(key,in_filename)
#decrypt_file(key, in_file)

# Another Approach
from Crypto import Random
from Crypto.Cipher import AES

def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

def encrypt(message, key, key_size=256):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")

def encrypt_f(file_name, plaintext, key):
    enc = encrypt(plaintext, key)
    out = file_name + ".enc"
    with open(out, 'wb') as fo:
        fo.write(enc)
    print "The encrypted file is: ", out

def decrypt_f(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
#    with open(file_name[:-4], 'wb') as fo:
 #       fo.write(dec)
    decmsg = base64.b64decode(dec)
    print "\nThe decrypted data is: ", decmsg


try:
    with open('mykey2.pem','r') as f2:
        key2 = RSA.importKey(f2.read(), passphrase='Secret pass')
        print "My key : ", key2
    with open('mykey3.enc','rb') as f2:
       encryptedkey = f2.read()

    print ' Ciphertext length: ',len(encryptedkey)
    rsakey = PKCS1_OAEP.new(key2)
    aeskey = rsakey.decrypt(encryptedkey)

    encrypt_f(in_filename, dropmsg, aeskey)
    decrypt_f(in_file, aeskey)

except EOFError:
    print " Can not open the file !!"