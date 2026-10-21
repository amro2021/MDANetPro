import os
import sys
import base64

# to check if the file is exist or not

File = "test.txt"

pa = os.path.dirname(os.path.realpath(__file__))
print "The directory is :", pa

execfile("filewrite.py")
try:
    if os.stat(pa+ "\\" + File).st_size > 0:
        print "Processing..."
        with open(File, "rb") as myfile:
            pickmsg = myfile.read()
            work = pickmsg.split()
        done = []
        for i in range(0, len(work)):
            msg = base64.b64decode(work[i])
            done.append(msg)
        print done
    else:
        print "Empty URL file ... exiting"
        sys.exit()
except OSError:
    print "URL file missing ... exiting"
    sys.exit()

# to get the current path of the script
# os.path.realpath(__file__)


