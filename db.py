#!/usr/bin/python
from peewee import *
#from playhouse.fields import ManyToManyField
# peewee database
db_node = SqliteDatabase('coffee.db', timeout=60.0)


class MdaModel(Model):
    class Meta:
        database = db_node


class Node(MdaModel):
    # include all information about every node in my networks
    hash = CharField()       # Hash of [ NodeID:Ikey:j_time ]
    nodeid = CharField()     # IP:PORT
    ContactID = CharField()     # ID of each original node in the Network
    Ikey = CharField()       # Public key for Integrity
    j_time = CharField()     # join time
    f_time = CharField()     # first message from this node
    weight = CharField()     # No. of records in nodelist
    Node_time = CharField()  # Last Node time

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
    # Include all information about every mda network i'm a member of it.
    name = CharField()  # Name of the network
    type = CharField()  # Public or Private
    rules = CharField()  # rules set by network members
    description = CharField()  # Description of the network
    nodes = ManyToManyField(Node, backref='networks')

    class Meta:
        database = db_node

NodeNetworks = Network.nodes.get_through_model()

db_node.connect()
db_node.create_tables([Node, Contact, Network, NodeNetworks])
db_node.close()


# --------------------------------------------------------------------------

