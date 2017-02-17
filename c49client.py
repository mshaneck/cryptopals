#!/usr/bin/python
from set2 import *
from set7 import *
import sys, getopt, socket
import urllib2
import requests
import urllib

baseurl='http:/localhost:5000/c49?'

def getMacValue(message):
    data={}
    data['message'] = message.encode("hex")
    url_values = urllib.urlencode(data)
    print url_values
    response = urllib2.urlopen('http://localhost:5000/c49?' + url_values)
    html = response.read()
    values = html.split("\n")
    if (len(values) == 1):
        print "Error"
        return ("", "", "")
    return values

def transferMoney(message, mac, iv):
    data={}
    data['message'] = message.encode("hex")
    if (iv != "NULL"):
        data['iv'] = iv
    data['mac'] = mac
    url_values = urllib.urlencode(data)
    print url_values
    response = urllib2.urlopen('http://localhost:5000/c49?' + url_values)
    html = response.read()
    print html
    return html[:6] == "Moving"

print "Get mac value:"
(message, iv, mac) = getMacValue("from=55&to=22&amount=4321")
print "Message: " + message
print "IV: " + iv
print "MAC: " + mac
print "Transfer money"
if (transferMoney(message, mac, iv)):
    print "TRANSFER!"
print "Now let's steal money since we can control the IV"
if (transferMoney("from=22&to=55&amount=4321", mac, "00"*5+"0707"+"00"*4+"0707"+"00"*3)):
    print "W00T! Stole the money!"

print "Now let's do it with a fixed IV and transaction lists"
invalidList = "from=55&tx_list=11:4321;44:2341;22:1231233112"
validList = "from=55&tx_list=11:4321;44:2341"
print "This one should work"
(message, iv, mac) = getMacValue(validList)
print "Message: " + message
print "IV: " + iv
print "MAC: " + mac

# print "This one should not"
# (message, iv, mac) = getMacValue(invalidList)
#
#
# M1 = "from=55&tx_list=11:4321;44:2341"
# (message, iv, mac) = getMacValue(M1)
# if (transferMoney(message, mac, "NULL")):
#     print "Money Transfered"
# M2 = "from=55&tx_list=11:4321;44:2341"
# getMacValue(M2)
#                   X               X
M1="from=55&tx_list=11:4321;44:234;122:671238;12:2345"
M2="tx_list=123:13;122:1000000&from=55"
(m1, iv1, mac1) = getMacValue(M1)
(m2, iv2, mac2) = getMacValue(M2)
print "Mac1: " + mac1
print "Mac2: " + mac2
m2mask = mac1 + "0"*(len(m2)*2 - len(mac1))
m2hex  = M2.encode("hex")
print m2mask
print m2hex
M3 = pkcs7Padding(M1,16)+hexxor(m2mask, m2hex).decode("hex")
print M3
# This isn't exactly going to work to get the money transferred, but it proves the point about CBCMAC length extensions...
if (transferMoney(M3, mac2, "NULL")):
    print "TRANSFER! We win!!!"
