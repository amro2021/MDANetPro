#!/usr/bin/python
from peewee import *
import ast
import time
#from playhouse.fields import ManyToManyField
#from peewee import ManyToManyField

# peewee database
db_node = SqliteDatabase('coffee.db', timeout=60.0)


class MdaModel(Model):
    class Meta:
        database = db_node


class Node(MdaModel):
    '''
    Include all information about every node in my networks.
    '''
    hash = CharField()       # Hash of [ NodeID:Ikey:j_time ]
    nodeid = CharField()     # IP:PORT
    ContactID = CharField()  # ID of each original node in the Network
    Ikey = CharField()       # Public key for Integrity
    j_time = CharField()     # join time
    f_time = CharField()     # first message from this node
    weight = CharField()     # No. of records in nodelist
    Node_time = CharField()  # Last Node time = ping time

    class Meta:
        database = db_node


class Contact(MdaModel):
    '''
    Include information about my contacts

    '''
    ContactID = CharField()     # ID of each original node in the Network
    name = CharField()       # Name in the user contacts

    class Meta:
        database = db_node


class Network(MdaModel):
    '''
    Include all information about every mda network i'm a member of it.
    '''
    name = CharField()  # Name of the network
    type = CharField()  # Public or Private
    rules = CharField()  # rules set by network members
    description = CharField()  # Description of the network
    nodes = ManyToManyField(Node, backref='networks')

    class Meta:
        database = db_node


NodeNetworks = Network.nodes.get_through_model()
# ---------------------------------------------------------------------
# Nodelist Database Operations


def enter_node(Hash, nodeid, NodeID, Ikey, j_time, f_time, n_time, weight='1'):
    # enter node info for the first time
    with db_node.atomic() as nt:
        uncle_bob = Node(hash=Hash, nodeid=nodeid, ContactID=NodeID, Ikey=Ikey, j_time=j_time, f_time=f_time, Node_time=n_time, weight=weight)
        uncle_bob.save()
    db_node.close()


def update_node(Hash, Nody):
    # update some info of the node if changed later
    with db_node.atomic() as nt:
        uncle_boo = Node.update(hash=Hash, nodeid=Nody.nodeid, ContactID=Nody.ContactID, Ikey=Nody.Ikey, j_time=Nody.j_time, f_time=Nody.f_time,weight=Nody.weight, is_relative=True)
        uncle_boo.execute()
    db_node.close()


def update_weight(d_query, we):
    # update weight in Node and Node database
    with db_node.atomic() as nt:
        qu = Node.select().where(Node.hash == d_query).get()
        qu.nodeid = we
        qu.save()
    db_node.close()


def get_node(d_flag, d_query):
    # get some info from the node
    try:
        with db_node.atomic() as nt:
            query = None
            if d_flag == "2":  # return hashes in string of list
                hashlist = []
                for node in Node.select():
                    hashlist.append(node.hash)
                query = str(hashlist)
            elif d_flag == '4':  # search by hash,  return nodeid
                qu = Node.select().where(Node.hash == d_query).get()
                query = qu.nodeid
            elif d_flag == '5':  # search by nodeid,  return hash
                qu = Node.select().where(Node.nodeid == d_query).get()
                query = qu.hash
            elif d_flag == '6':  # check for the exists, return NodeID
                qu = Node.select().where(Node.ContactID == d_query)
                if qu.exists():
                    qu1 = Node.select().where(Node.ContactID == d_query).get()
                    query = qu1.nodeid
                else:
                    query = False
            elif d_flag == '7':  # check for the exists, return hash
                qu = Node.select().where(Node.ContactID == d_query)
                if qu.exists():
                    qu1 = Node.select().where(Node.ContactID == d_query).get()
                    query = qu1.hash
                else:
                    query = False
            elif d_flag == '8':  # check for the exists, return hash
                qu = Node.select().where(Node.nodeid == d_query).get()
                query = qu.nodeid
        db_node.close()

        return query
    except:
        return False

def get_ikey(contactid):
    try:
        with db_node.atomic() as nt:
            query = None
            qu = Node.select().where(Node.ContactID == contactid).get()

            query = qu.Ikey
        db_node.close()
        return query
    except:
        return False


def update_ikey(contactid, ikey):
    try:
        with db_node.atomic() as nt:
            query = None
            qu = Node.select().where(Node.ContactID == contactid).get()
            qu.Ikey = ikey
            qu.save()
        db_node.close()
        return query
    except:
        return False


def check_node(d_query):
    # check if node in the nodelist
    query = None
    # search by hash
    sa = Node.select().where(Node.hash == d_query)
    if sa.exists():
        query = True
    else:
        query = False
    return query


def len_node():
    # get the length of the nodelist
    with db_node.atomic() as nt:
        x = len(Node.select())
    db_node.close()
    return x


def del_node(Nodeid):
    # delete the node from the list
    with db_node.atomic() as nt:
        uncle_boo = Node.get(Node.hash == Nodeid)
        uncle_boo.delete_instance()
    db_node.close()


# ---------------------------------------------------------
# Ping Operations


def update_ping(d_query, ping_time):
    # check if node in the Nodelist
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa = Node.select().where(Node.hash == d_query).get()
        sa.Node_time = ping_time
        sa.save()
    db_node.close()


def check_ping(d_query):
    # check if node in the nodelist
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa1 = Node.select().where(Node.hash == d_query)
        if sa1.exists():
            sa = Node.select().where(Node.hash == d_query).get()
            if sa.Node_time < '1000':
                query = True
            else:
                query = False
        else:
            query = False
    db_node.close()
    return query

# ---------------------------------------------------------
# Contact Table Operations


def enter_contact(name, id):
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa = Contact.select().where(Contact.ContactID == id)
        if sa.exists():
            query = True
        else:
            new_contact = Contact(name=name, ContactID=id)
            new_contact.save()
    db_node.close()

    return query


def check_contact(id):
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa = Contact.select().where(Contact.ContactID == id)
        if sa.exists():
            query = True
        else:
            query = False
    db_node.close()

    return query


def get_contact(id):
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa1 = Contact.select().where(Contact.ContactID == id)
        if sa1.exists():
            sa = Contact.select().where(Contact.ContactID == id).get()
            query = sa.name
        else:
            query = "No name"
    db_node.close()

    return query


def get_name(name):
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa = Contact.select().where(Contact.name == name).get()
        query = sa.ContactID
    db_node.close()

    return query


def del_contact(name):
    # delete the node from the list
    with db_node.atomic() as nt:
        unwanted_contact = Contact.get(Contact.name == name)
        unwanted_contact.delete_instance()
        unwanted_contact.save()
    db_node.close()


def get_all_contacts():
    query = []
    # search by hash
    with db_node.atomic() as nt:
        sa = Contact.select(Contact.name)
        for i in sa:
            query.append(i.name)
    db_node.close()

    return query

# ---------------------------------------------------------
# Network table Operations


def add_net_nodes(ha, nodeid, net_name): #  make use of enter_node function
    query = None
    # search by hash
    with db_node.atomic() as nt:
        sa1 = Node.select().where(Node.hash == ha)
        if sa1.exists():
            sa = Node.select().where(Node.hash == ha).get()
            sa.nodeid = nodeid
        else:
            uncle_bob = Node(hash=ha, nodeid=nodeid, ContactID="", Ikey="", j_time=str(time.time()), f_time="", weight="", Node_time="")
            uncle_bob.save()

        bob = Node.select().where(Node.hash == ha).get()
        network0 = Network.select().where(Network.name == net_name)
        if network0.exists():
            network0 = Network.get(Network.name == net_name)
            bob.networks.add(network0)
            bob.save()
    db_node.close()


def get_net_nodes(net_name):
    net_nodes = {}

    # Get all nodes in a net:
    with db_node.atomic() as nt:
        net = Network.get(Network.name == net_name)
    db_node.close()
    for node in net.nodes:
        net_nodes.update({node.hash: node.nodeid})
        #print "get node : ", node.hash

    return net_nodes


def get_full_net_nodes(net_name):
    net_nodes = {}
    # Get all nodes in a net:
    with db_node.atomic() as nt:
        net = Network.get(Network.name == net_name)
    db_node.close()
    for node in net.nodes:
        if node.ping_time < 20:
            net_nodes.update({node.hash: node})

    return net_nodes


def check_weight(net_name):
    net_nodes = get_net_nodes(net_name)
    # Return the max weight in weight list
    with db_node.atomic() as nt:
        maxweight = None
        ha = None
        for hash, nodeid in net_nodes.iteritems():
            qu = Node.select().where(Node.hash == hash).get()
            if qu.weight > maxweight:
                maxweight = qu.weight
                ha = qu.hash
            else:
                continue
    db_node.close()
    return maxweight, ha


def get_node_networks(node_hash):
    node_nets = []
    # Get all networks that nody is enrolled in:
    with db_node.atomic() as nt:
        nody = Node.get(Node.hash == node_hash)
    db_node.close()
    for network in nody.networks.order_by(Network.name):
        node_nets.append(network.name)

    return node_nets


def add_network(net_name, net_type, net_des, net_rules, selected_nodes):

    with db_node.atomic() as nt:
        uncle_bob = Network(name=net_name, type=net_type, rules=net_rules, description="")
        uncle_bob.save()
    db_node.close()

    net_nodes = ast.literal_eval(selected_nodes)
    for key, value in net_nodes.iteritems():
        #print "Key: ", key
        #print "Value: ", value
        add_net_nodes(key, value, net_name)


def select_nodes(net):
    # Select nodes to be in network profile
    nodes = "\n"
    net_nodes = get_net_nodes(net)
    nodes = str(net_nodes)
    return nodes

'''
q = get_node('7','KLQ3RQ0JBXBCQIXV58D5W6L7B93P6K')
#p = get_net_nodes('test15')
l = get_node_networks(q)
#s = get_all_contacts()
print "q: ",q
#print "p: ",p
print "l: ", l
#print s

from encryption import mda_encryption

import json
import base64
o, key = mda_encryption.generateRSAkey(op='mda1')
iikey = unicode(o, "ascii")
#update_ikey('R1JVQGE2GKHYTNYKOXD80MIPTA9M7O', iikey)
iiii = get_ikey('R1JVQGE2GKHYTNYKOXD80MIPTA9M7O')
print 'iiii', iiii, type(iiii)

import unicodedata
sss = unicodedata.normalize('NFKD', iiii).encode('ascii','ignore')
from Crypto.PublicKey import RSA
race1 = json.loads(sss)
qq = base64.b64decode(race1)
query = RSA.importKey(qq)
print query, type(query)
'''