#!/usr/bin/python
from set2 import *
from set7 import *
from flask import Flask
from flask import request
app = Flask(__name__)
consistentKey = ""

@app.route("/")
def hello():
    return "Please go to /c49 for the challenge site..."

@app.route("/c49")
def c49():
    if (request.args.get('message')):
        message = request.args.get('message').decode("hex")
        #print "Got: " + message
        if (request.args.get('mac')):
            #from=#{from_id}&to=#{to_id}&amount=#{amount}
            msgParts = message.split("&")
            mac = request.args.get('mac').decode("hex")
            msg = dict(s.split('=') for s in msgParts)

            if (request.args.get('iv')):
                iv = request.args.get('iv').decode("hex")
            else:
                iv = "\x00"*16
            # print message
            # print mac
            # print consistentKey
            # print iv

            if (verifyCbcMac(message, mac, consistentKey, iv)):
                if ("from" in msg):
                    if ("to" in msg):
                        return "Moving %s from account %s to account %s" % (msg["amount"], msg["from"], msg["to"])
                    if ("tx_list" in msg):
                        return "Moving : Do the list " + msg["tx_list"]
                    return "No to account(s)"
                else:
                    return "No from account"
            else:
                return "I don't think so. You are a fake"
            #return "Challenge 49: <br>Message= %s<br>IV=%s<br>MAC=%s" % (request.args.get('message'), request.args.get('iv'), request.args.get('mac'))
        else:
            msgParts = message.split("&")
            msg = dict(s.split('=') for s in msgParts)
            if ("from" in msg and msg["from"] == "55"):
                if ("tx_list" in msg):
                    #make sure we don't send money to 22!
                    tx_parts = msg["tx_list"].split(";")
                    txdict = dict(s.split(":") for s in tx_parts)
                    # if ("22" in txdict):
                    #     print "I don't think so..."
                    #     return "Bad Account. No transfer!"
                iv = request.args.get('iv')
                if (not iv):
                    iv = "\x00"*16
                mac = genCbcMac(message, consistentKey, iv)
                return message + "\n" + iv.encode("hex") + "\n" + mac.encode("hex")
            else:
                return "Not authorized!"

    else:
        return "No message"

if __name__ == "__main__":
    consistentKey = getRandomAESKey()
    app.run()
