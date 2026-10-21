#!/usr/bin/python
import threading
import datetime
from peewee import *
import mdanetwork as f
# peewee database
db = SqliteDatabase('coffeetest.db', threadlocals=True, timeout=60.0)
db_node = SqliteDatabase('coffee.db', threadlocals=True, timeout=60.0)
db_ping = SqliteDatabase('bee.db', threadlocals=True, timeout=60.0)
db_contact = SqliteDatabase('melissa.db', threadlocals=True, timeout=60.0)


class Node(Model):
    # include all information about every node
    hash = CharField()       # Hash of [ ContactID:Ikey:j_time ]
    nodeid = CharField()     # IP:PORT
    ContactID = CharField()  # ID of each original node in the Network
    Ikey = CharField()       # Public key for Integrity
    j_time = CharField()     # join time
    f_time = CharField()     # first message from this node
    weight = CharField()     # No. of records in nodelist

    class Meta:
        database = db_node


class Ping(Model):
    # include ping nodes only
    hash = CharField()       # Hash of [ ContactID:Ikey:j_time ]
    ping_time = CharField()  # Last ping time

    class Meta:
        database = db_ping


class Contact(Model):
    # include contact related-info only
    name = CharField()       # Name in the user Contacts list
    hash = CharField()       # Hash of [ ContactID:Ikey:j_time ]
    ContactID = CharField()  # ID of each original node in the Network
    ping_time = CharField()  # Last ping time

    class Meta:
        database = db_contact


# ---------------------------------------------------------------------

''' # For db_test ONLY ***************
class Node(Model):
    hash = CharField()
    IP = IntegerField()
    ContactID = CharField()
    Ikey = CharField()
    j_time = CharField()
    f_time = CharField()
    weight = CharField()
    is_relative = BooleanField()

    class Meta:
        database = db
'''

db_node.connect()
db_node.create_tables([Node])
db_node.close()



def enter_data():
    db.connect()
    with db.atomic() as nt:
        for i in range(0, 50):
            hash = "21332344cfg35465{}".format(i)
            IP = 2134567896543
            ContactID = "324trghf{}bvf2fr39e{}rfug9j3u3ifvf".format(i,i)
            Ikey = "324546ty{}ujghfddsfrrhy54r54y{}thgfbd".format(i,i)
            j = i + 1
            k = i + 2
            if i > 29:
                j = i - 29
                k = i - 28
            j_time = str(datetime.date(1961, 1, j))
            f_time = str(datetime.date(1961, 1, k))
            weight = str(IP) + hash
            uncle_bob = Node(hash=hash, IP=IP, ContactID=ContactID, Ikey=Ikey, j_time=j_time, f_time=f_time, weight=weight, is_relative=True)
            uncle_bob.save()
    db.close()
    print (threading.currentThread(), " finished")


def modify_data():
    db.connect()
    with db.atomic() as nt:
        for i in range(0, 5):
            hash = "2133234435465{}dgvf454{}hf".format(i,i*3)
            IP = 2134567896543345691+ i*7
            ContactID = "32fweurhndjhgndjfbjjdnfjhdifudusnf4trghf{}bvf239e{}rfug9j3u3ifvf".format(i,i)
            Ikey = "324546ty{}ujghfddsfhsvdfffffffffvrtrdbtnfgmjrterfr435tberg8rvnu4v9begyf8evn8yet8274nr909iweverby9i4h4n9ger8vfubgn3uhndb9gu3gnwe9bu3nfbfwer3o4{}itvnoweijfy54r54y{}thgfbd".format(i,i,i*i)
            j = i + 1
            k = i + 2
            '''if i > 29:
                j = i - 29
                k = i - 28'''
            j_time = datetime.date(1960, 1, j)
            f_time = datetime.date(1960, 1, k)

            uncle_bob = Node(hash=hash, IP=IP, ContactID=ContactID, Ikey=Ikey, j_time=j_time, f_time=f_time, is_relative=True)
            uncle_bob.save()
        db.close()
    print (threading.currentThread(), " finished")


def reteif_data():
    db.connect()
    print ("No of Records: ", len(Node.select()))
    query = Node.select().where(Node.hash=="21332344cfg3546548").get()
    print (type(query))
    print ("Get some records: ", query.IP, "  ", query.Ikey)
    print ("Hash Table")
    print ("Hash                              ", "Ikey")
    print ("------------------------------------------------")
    #for node in Node.select():
     #   print node.hash, "                   ", node.Ikey
    db.close()
    print (threading.currentThread())

# ----------------------------------------------------

'''
d_query= '2354654ytrhgfe'
sa = Node.select().where(Node.hash == d_query)
if sa.exists():
    print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    print "The check is complete, Record exist."
else:
    print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    print "The check is complete, Record does not exist."
'''



# -----------------------------------------------
'''add = 1
try:
    if add == 1:

        #thread7 = threading.Thread(target=reteif_data)
        #thread7.start()
        for i in range(0, 10):
            thread = threading.Thread(target=enter_data)
            thread.start()

            #thread2 = threading.Thread(target=modify_data)
            #thread2.start()
            thread3 = threading.Thread(target=modify_data)
            thread3.start()
            thread4 = threading.Thread(target=enter_data)
            thread4.start()
            thread5 = threading.Thread(target=modify_data)
            thread5.start()
            thread6 = threading.Thread(target=enter_data)
            thread6.start()
            thread8 = threading.Thread(target=modify_data)
            thread8.start()

        #thread9 = threading.Thread(target=reteif_data)
        #thread9.start()

        #thread10 = threading.Thread(target=reteif_data)
        #thread10.start()
        #thread10.join()
except OperationalError:
    pass
'''
# ------------------------------------------------------

'''
from Crypto.Hash import SHA512
import string

def generate_hash(nodeid, contactid, Ikey):
        key = ''.format(nodeid,contactid,Ikey)
        h = SHA512.new()
        h.update(key)
        print "####", h.digest_size
        return h.hexdigest()

no = ''
co = ''
I = ''

h = generate_hash(no, co, I)
sh = str(h)
print ("The generated hash: ", h)
print (type(h), "  ,   ", len(h))
'''

# -----------------------------------------------------



