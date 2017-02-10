#!/usr/bin/python

from flask import Flask
from flask import request
app = Flask(__name__)

@app.route("/")
def hello():
    return "Please go to /c49 for the challenge site..."

@app.route("/c49")
def c49():
    if (request.args.get('message')):
        message = request.args.get('message')
        if (request.args.get('mac')):
            #from=#{from_id}&to=#{to_id}&amount=#{amount}
            msgParts = message.split("&")
            msg = dict(s.split('=') for s in msgParts)
            return "Maybe moving %s from account %s to account %s" % (msg["amount"], msg["from"], msg["to"])
            #return "Challenge 49: <br>Message= %s<br>IV=%s<br>MAC=%s" % (request.args.get('message'), request.args.get('iv'), request.args.get('mac'))
        else:
            return "Need to calculate the MAC!"
    else:
        return "No message"

if __name__ == "__main__":
    app.run()
