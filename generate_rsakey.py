from Crypto.PublicKey import RSA
from Crypto.Util import randpool
from Crypto.Cipher import PKCS1_OAEP
import base64, sys
import json
from Crypto import Random
import Tkinter as tk
import ttk

def generateRSAkey():

        # generate the RSA key ( for the AES key )
        blah = randpool.RandomPool()
        RSAKey = RSA.generate(2048, blah.get_bytes)

        RSAPubKey = RSAKey.publickey()
        pri = RSAKey.exportKey(format='PEM', passphrase='Secret pass',pkcs=1)
        pup = RSAPubKey.exportKey(format='PEM', passphrase='Secert key',pkcs=1)

        #send the public key over
        race1 = base64.b64encode(pup)
        go = json.dumps(race1)
        #print " sending the public-key", pup
        #print " the encoded key", race1

        return pri, RSAPubKey, RSAKey

pri, pup, rsa = generateRSAkey()

key = Random.new().read(32)
rsakey = PKCS1_OAEP.new(pup)

encryptedkey = rsakey.encrypt(key)

print "The key before", rsa.publickey()
print "PEM format: ", pri
print "PEM format: ", pup
with open('mykey2.pem','wb') as f:
    f.write(pri)

print ' Ciphertext length: ',len(encryptedkey)

with open('mykey3.enc','wb') as f:
    f.write(encryptedkey)

#with open('mykey2.pem','r') as f2:
 #   key2 = RSA.importKey(f2, passphrase='Secert password')

#print "after:: ", key2



class Dialog(tk.Toplevel):

    '''Class to open dialogs.

    This class is intended as a base class for custom dialogs
    '''

    def __init__(self, parent, title=None, passph='sec'):

        '''Initialize a dialog.

        Arguments:

            parent -- a parent window (the application window)

            title -- the dialog title
        '''
        tk.Toplevel.__init__(self, parent)
        self.configure(bg="white")

        s = ttk.Style()
        s.configure('TLabel', background='white', foreground="#000000")
        s = ttk.Style()
        s.configure('RED.TLabel', background='white', foreground="#ff0000")
        s3 = ttk.Style()
        s3.configure('TFrame', background='white', foreground="#000000")

        self.tryc = 0
        self.va = 0

        self.passphrase = passph    # For test only
        self.withdraw() # remain invisible for now
        # If the master is not viewable, don't
        # make the child transient, or else it
        # would be opened withdrawn
        if parent.winfo_viewable():
            self.transient(parent)

        if title:
            self.title(title)

        self.parent = parent

        self.result = None

        body = ttk.Frame(self)
        self.initial_focus = self.body(body)
        body.pack(padx=5, pady=5)

        self.buttonbox()

        if not self.initial_focus:
            self.initial_focus = self

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        self.center(self)
        #if self.parent is not None:
         #   self.geometry("+%d+%d" % (parent.winfo_rootx()+50,
          #                            parent.winfo_rooty()+50))

        self.deiconify() # become visible now

        self.initial_focus.focus_set()

        # wait for window to appear on screen before calling grab_set
        self.wait_visibility()
        self.grab_set()
        self.wait_window(self)

    def destroy(self):
        '''Destroy the window'''
        self.initial_focus = None
        tk.Toplevel.destroy(self)

    #
    # construction hooks

    def body(self, master):
        '''create dialog body.

        return widget that should have initial focus.
        This method should be overridden, and is called
        by the __init__ method.
        '''
        frame = ttk.Frame(self)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        frame.columnconfigure(0, weight=3)
        frame.columnconfigure(1, weight=3)
        #frame.columnconfigure(2, weight=3)
        frame.rowconfigure(0, weight=3)

        # The Name, id label
        namelbl = ttk.Label(frame, text="Enter Password :")

        # Enter your friend name and id
        self.pavar = tk.StringVar()
        name = ttk.Entry(frame, textvariable=self.pavar, show='*')

        namelbl.grid(row=0, column=0, sticky=tk.E+tk.W+tk.S+tk.N)
        name.grid(row=0, column=1, sticky=tk.E+tk.W+tk.S+tk.N, padx=3)

        self.warn = tk.StringVar()
        namelbl = ttk.Label(frame, textvariable=self.warn, style='RED.TLabel')
        namelbl.grid(row=1, column=0, columnspan=2, sticky=tk.E+tk.W+tk.S+tk.N, pady=3)


    def buttonbox(self):
        '''add standard button box.

        override if you do not want the standard buttons
        '''

        box = ttk.Frame(self)

        w = ttk.Button(box, text="OK", width=10, command=self.ok)
        w.grid(row=0, column=0, padx=5, sticky=tk.E+tk.N)
        w = ttk.Button(box, text="Cancel", width=10, command=self.cancel)
        w.grid(row=0, column=1, padx=5, sticky=tk.E+tk.N)

        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)

        box.pack()

    #
    # standard button semantics

    def ok(self, event=None):
        self.va = self.validate()
        if not self.va and self.tryc <= 3:
            self.initial_focus.focus_set() # put focus back
            self.tryc += 1
            return

        self.withdraw()
        self.update_idletasks()

        try:
            self.apply()
        finally:
            self.destroy()

    def cancel(self, event=None):

        # put focus back to the parent window
        #if self.parent is not None:
            #self.parent.focus_set()
        self.destroy()
        sys.exit(0)

    def validate(self):
        '''validate the data

        This method is called automatically to validate the data before the
        dialog is destroyed. By default, it always validates OK.
        '''
        if self.pavar.get() == self.passphrase:

            return 1 # override
        else:
            self.warn.set('The password is not correct !')
            return 0

    def apply(self):
        '''process the data

        This method is called automatically to process the data, *after*
        the dialog is destroyed. By default, it does nothing.
        '''

        pass # override
