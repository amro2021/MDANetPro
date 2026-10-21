#!/usr/bin/python
import threading
import time
from mdanetwork import mda, mdaconnection
import db_dht as db
import socket

# -----------------------------------------------------
# %%%%%%%%%%%Change to test%%%%%%%%%%%%%%%%%%%
# Make the first Node in the MDA-Network
# %%%%%%%%%%%Change to test%%%%%%%%%%%%%%%%%%%


def make_node():
    host = ''

    # %%%%%%%%%%%Change to test%%%%%%%%%%%%%%%%%%%
    PORT = 44444
    IP = socket.gethostbyname(socket.gethostname())
    nodeid = IP + ':' + str(PORT)   # My nodeid send it as Sender of messages
    inta = mda()
    newnodekey = str(inta.generatkey(44))
    print newnodekey
    j_time = str(time.time())
    f_time = str(time.time())
    d, ikey = mdaconnection.generateRSAkey()
    key = str(ikey)
    ha = str(mda.generate_hash(str(nodeid), newnodekey, ikey))
    db.enter_node(ha, str(nodeid), newnodekey, key, j_time, f_time)
    db.enter_ping(ha, j_time)


#make_node()

PORT = 44444
IP = socket.gethostbyname(socket.gethostname())
nodeid = IP + ':' + str(PORT)   # My nodeid send it as Sender of messages
print  nodeid
ha = db.get_node('5', nodeid)
#has = str(ha)
j_time = db.get_node('8', nodeid)
p_time = db.get_ping('1', ha)
print ha, "   ", type(ha)
#print has, "   ", type(has)
print j_time, "   ", type(j_time)
print p_time, "   ", type(p_time)
