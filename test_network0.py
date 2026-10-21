
# ########################################
# ########################### TEST TEST

import db_dht as db
from net_profile import mdar

from Crypto.Hash import SHA512
import random
import string
import ast
import time


def test():
    print( "This is a test to make a .mdar file")
    net_name = raw_input('Enter the network name: ')
    t_type = raw_input('Enter the network type(private or public): ')
    net_description = raw_input('Enter the network description: ')
    net_rules = raw_input('Enter the network rules: ')
    test_mdar = mdar()
    nodes = test2()
    test_mdar.make_mdar(str(net_name), str(t_type), str(net_description), str(net_rules),nodes)
    db.add_network(net_name, t_type, net_description, net_rules, nodes)
    print ("\nReading the net file....")
    net_name, net_type, net_des, net_rules, selected_nodes = test_mdar.read_mdar(str( net_name +".mdar"))
    print ("net_name: ", net_name)
    print ("net_type: ", net_type)
    print ("net_des: ", net_des)
    print ("net_rules: ", net_rules)
    print ("selected_nodes: ", selected_nodes, type(selected_nodes))
    net_nodes = ast.literal_eval(selected_nodes)
    #for key, value in net_nodes.iteritems():
     #   print "Key: ", key
      #  print "Value: ", value
    exit(0)


def test2():
    print ("Generating the testing nodes")
    net_nodes = {}
    n = ['192.168.80.128:50404', '192.168.80.131:50404', '192.168.80.135:50404', '192.168.80.130:50404']
    print (len(n))
    for x in range(0 ,4):
        c = generatkey(30)
        h = str(generate_hash(c, ""))
        print ("Node No.{}: ".format(x), h, "  ", n[x], "    ", c)

        net_nodes.update({h: n[x]})

        db.enter_node(h ,n[x] ,c ,"" ,str(time.time()),"", str(time.time()))

    print ("\nnet_nodes: ", type(net_nodes))
    nodes = str(net_nodes)
    return nodes


def generate_hash(contactid, Ikey):
    """
    Generate SHA hash
    :param contactid: MDA ID
    :param Ikey: RSA key
    :return:
    """
    key = '{}{}'.format(contactid, Ikey)
    h = SHA512.new()
    h.update(key)
    return h.hexdigest()



def generatkey(N):
    """
    Generate a new contact key
    :param N: Length of Contact key
    :return: Generated key
    """
    generatedkey = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))
    return generatedkey




# run the test
test()