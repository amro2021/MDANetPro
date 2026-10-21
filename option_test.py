import Tkinter as tk
import ttk
import sys
import mdanetwork as mda


class options(ttk.Frame):

    def __init__(self, parent):
        ttk.Frame.__init__(self, parent)
        self.parent = parent
        s = ttk.Style()
        s.configure('TLabel', background='white', foreground="#000000")
        s2 = ttk.Style()
        s2.configure('TCheckbutton', background='white', foreground="#000000")
        s3 = ttk.Style()
        s3.configure('TFrame', background='white', foreground="#000000")
        s4 = ttk.Style()
        s4.configure('TSeparator', background='white', foreground="#000000")

        self.mdaoptions()

    def mdaoptions(self):
        self.parent.title("Options")
        self.pack(fill=tk.BOTH, expand=True)
        # top = Toplevel()
        # top.title("Options")

        frame = ttk.Frame(self.parent, style='TFrame')
        frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)

        frame.columnconfigure(0, weight=3)
        frame.columnconfigure(1, weight=3)
        frame.rowconfigure(0, weight=3)

        # General options
        lbl = ttk.Label(frame, text='General')

        lbl.grid(row=0, column=0, sticky=tk.N+tk.W)

        self.passvar = tk.IntVar()
        self.cashvar = tk.IntVar()
        showvar = tk.StringVar()
        iconvar = tk.StringVar()
        unkvar = tk.StringVar()

        box1 = ttk.Checkbutton(frame, text='Use general password: ', variable=self.passvar, command=self.usepass)
        pas = tk.StringVar()
        self.passent = ttk.Entry(frame, textvariable=pas, state='disabled')
        box1.grid(row=1, column=0, sticky=tk.N+tk.W)
        self.passent.grid(row=1, column=1, pady=3, sticky=tk.N+tk.W+tk.E)

        box2 = ttk.Checkbutton(frame, text='Cash messages for (in days)', variable=self.cashvar, command=self.cash)
        box2.grid(row=2, column=0, sticky=tk.N+tk.W)
        self.cashspin = tk.Spinbox(frame, from_=0, to=100, width=3, state='disabled')
        self.cashspin.grid(row=2, column=1, sticky=tk.W+tk.N)

        box3 = ttk.Checkbutton(frame, text='Show new messages in new windows', variable=showvar)
        box4 = ttk.Checkbutton(frame, text='Iconify the program windows when minimize it.', variable=iconvar)
        box5 = ttk.Checkbutton(frame, text='Do not receive from unknown members', variable=unkvar)
        box3.grid(row=3, column=0, columnspan=2, sticky=tk.N+tk.W)
        box4.grid(row=4, column=0, columnspan=2, sticky=tk.N+tk.W)
        box5.grid(row=5, column=0, columnspan=2, sticky=tk.N+tk.W)

        lbl1 = ttk.Label(frame, text='program language: ')
        drop = ttk.Combobox(frame, state='readonly', width="7")
        drop['values'] = ('English', 'Arabic')
        drop.current(0)

        drop.grid(row=6, column=1, sticky=tk.W+tk.N)
        lbl1.grid(row=6, column=0, sticky=tk.N+tk.W)

        se = ttk.Separator(frame)
        se.grid(row=7, column=0, columnspan=2,pady=5, sticky=tk.E+tk.W)
        # Security  options
        lbl3 = ttk.Label(frame, text='Security')
        lbl3.grid(row=8, column=0, sticky=tk.N+tk.W)

        self.qvar = tk.IntVar()
        box6 = ttk.Checkbutton(frame, text='Use verify question', variable=self.qvar, command=self.check)
        lbl4 = ttk.Label(frame, text='Enter the verify question: ')
        lbl5 = ttk.Label(frame, text='Enter the answer: ')
        ques = tk.StringVar()
        ans = tk.StringVar()
        self.quesent = ttk.Entry(frame, textvariable=ques, state='disabled')
        self.ansent = ttk.Entry(frame, textvariable=ans, state='disabled')
        box6.grid(row=9, column=0, sticky=tk.N+tk.W)
        lbl4.grid(row=10, column=0, sticky=tk.N+tk.W)
        lbl5.grid(row=11, column=0, sticky=tk.N+tk.W)
        self.quesent.grid(row=10, column=1, pady=3, sticky=tk.N+tk.W+tk.E)
        self.ansent.grid(row=11, column=1, sticky=tk.N+tk.W+tk.E)

        # Action Buttons
        frame2 = ttk.Frame(frame)
        frame2.grid(row=12, column=1, columnspan=2, sticky=tk.E)
        b1 = ttk.Button(frame2, text='Save', command=self.about)
        b2 = ttk.Button(frame2, text='Cancel', command=self.__exit__)
        b1.grid(row=0, column=0, padx=5, pady=3, sticky=tk.W+tk.N)
        b2.grid(row=0, column=1, pady=3, sticky=tk.E+tk.N)

    def usepass(self):
        if self.passvar.get() == 0:
            self.passent.configure(state='disabled')
        else:
            self.passent.configure(state='normal')

    def cash(self):
        if self.cashvar.get() == 0:
            self.cashspin.configure(state='disabled')
        else:
            self.cashspin.configure(state='normal')

    def check(self):
        if self.qvar.get() == 0:
            self.quesent.configure(state='disabled')
            self.ansent.configure(state='disabled')
        else:
            self.quesent.configure(state='normal')
            self.ansent.configure(state='normal')

    def about(self):
        top = tk.Toplevel()
        top.title("About")
        top.configure(bg="white")
        frame = ttk.Frame(top)
        frame.pack(fill=tk.BOTH, expand=True, pady=5, padx=5)

        frame.columnconfigure(0, weight=3)
        frame.columnconfigure(1, weight=3)
        frame.rowconfigure(0, weight=3)

        we = "MDA Private Messenger Edition 1.0\n"
        we2 = "Free, Secure and Anonymous Instant-Messaging Network\n\n"
        me = "Created by Amr Abdelnaser, 20/03/2016 04:00PM, Doha, Qatar\n"
        me2 = "Follow me in twitter: "
        me3 = "@AmrBsheer\n"
        us = "For more info, see MDA-Network blog: "
        us2 = "mdanetwork.wordpress.com\n\n"
        ack = "Acknowledgments\n"
        ack2 = "Abdallah Elsamman, Mohammed Elsayed"
        about = '{}{}{}{}{}{}{}{}{}'.format(we, we2, me, me2, me3, us, us2, ack, ack2)
        msg = ttk.Label(frame, text=about, justify=tk.CENTER, font=('arial', '12', 'bold'))
        msg.grid(row=0, column=0,  columnspan=2, padx=7, pady=7, sticky=tk.N+tk.W)
        button = ttk.Button(frame, text="Dismiss", command=top.destroy)
        button.grid(row=1, column=1, sticky=tk.N+tk.E)

        top.grab_set()

    def __exit__(self):
        self.parent.destroy()
        sys.exit(0)


class Dialog(tk.Toplevel):

    '''Class to open dialogs.

    This class is intended as a base class for custom dialogs
    '''

    def __init__(self, parent, title=None):

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
        self.passphrase = 'sec'
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

        center(self)
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


def center(toplevel):
    toplevel.update_idletasks()
    w = toplevel.winfo_screenwidth()
    h = toplevel.winfo_screenheight()
    size = tuple(int(_) for _ in toplevel.geometry().split('+')[0].split('x'))
    x = w/2 - size[0]/2
    y = h/2 - size[1]/2
    toplevel.geometry("%dx%d+%d+%d" % (size + (x, y)))

def main():
    root = tk.Tk()
    root.withdraw()
    #root.iconify()
    option = 1
    #nodelist, weightlist, mycontactid, weight, nameslist, options = mda.mda.get_config()
    if option == 1:
        pe = Dialog(root, title='Enter password')
        root.configure(background='#FFFFFF')
        check = pe.va
    else:
        check = 1

    if check == 1:
        root.update()
        root.deiconify()
        app = options(root)
        root.configure(background='#FFFFFF')
        center(root)
        root.mainloop()
    else:
        root.destroy()
        sys.exit(0)


if __name__ == '__main__':
    main()
