#!/usr/bin/python
import web
import time
from hashing import *
from Crypto.Random import random

urls = (
          '/test', 'test'
)



class test:
    hmacKey = random.choice(open("/usr/share/dict/words").readlines()).rstrip()

    def GET(self):
        user_data = web.input()
        #web.internalerror(self)
        mac = hmac_sha1(self.hmacKey, open(user_data.file).read())
        print "Debug: " + mac
        print "Debug: " + user_data.signature
        if (insecure_compare(mac, user_data.signature)):
            return "Signature is valid!"
        else:
            web.internalerror(self)
            return "Signature verification failed! Should have been " + mac

        #file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51

def insecure_compare(str1, str2):
    if (len(str1) <= len(str2)):
        length = len(str1)
    else:
        length = len(str2)
    for i in range(0,length):
        if (str1[i] != str2[i]):
            return False
        time.sleep(0.05) # Sleep for 50 ms
    # It's not right if the lengths are different
    if (len(str1) != len(str2)):
        return False
    return True

if __name__ == "__main__":

    app = web.application(urls, globals())
    app.run()
