from uuid import getnode as get_mac
mac = get_mac()
print "My MAC address is: ", mac
if (mac >> 40)%2 :
    raise OSError, "The system does not seem to have a valid MAC"
