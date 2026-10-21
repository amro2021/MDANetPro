# import random, hashlib, os, string


k = 100
# From the start node, find the node responsible
# for the target key
def findNode(start, key):
    current=start
    while distance(current.id, key) > \
          distance(current.next.id, key):
        current=current.next
    return current

# Find the responsible node and get the value for
# the key
def lookup(start, key):
    current=findFinger(start, key)
    next=findFinger(current, key)
    while distance(current.id, key) > \
          distance(next.id, key):
        current=next
        next=findFinger(current, key)
    return current

# Find the responsible node and store the value
# with the key
def store(start, key, value):
    node=findNode(start, key)
    node.data[key]=value

def update(node):
    for x in range(k):
        oldEntry=node.finger[x]
        node.finger[x]=findNode(oldEntry,
                          (node.id+(2**x)) % (2**k))

def findFinger(node, key):
    current=node
    for x in range(k):
        if distance(current.id, key) > \
           distance(node.finger[x].id, key):
            current=node.finger[x]
    return current



def distance(a, b):
    return a^b # In Python, this means a XOR b,
               # not a to the power of b.

'''
def __main__():
    id=int(random.uniform(0,2**k))
    node=Node(id)
    join(node, initialContact)

    line=raw_input('Enter an IP to scan: ').trim()
    key=long(hashlib.new(line).hexdigest(),16)
    value=lookup(node, key)
    if value==None:
        f=os.popen('nmap '+args[1])
        lines=f.readlines()
        value=string.join(lines, '\n')
        store(node, key, value)
'''
