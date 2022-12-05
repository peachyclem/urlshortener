'''
Author: Sareena Finner
Project: Url Shortener
'''

from flask import Flask, redirect, url_for,render_template, request,make_response
import re
from tinydb import TinyDB, Query
import time
from user_agents import parse
import string
import random

# url Ids are base64 encoding of an incremented integer.
import base64

import hashlib

# regex to check if the string is a url
httpPattern = re.compile("(https?:\/\/)?[a-zA-Z\-]+(\.[a-zA-Z\-]+)+")
# the url this is hosted on
siteDomain = "http://localhost:5000/"

app = Flask(__name__)

urlDatabase = TinyDB('urlDatabase.json')
redirectDatabase = TinyDB('redirectDatabase.json')
userDatabase = TinyDB('userDatabase.json')


count = 0
# when the server loads up, it gets the last inserted id to not lose track of the id sequence.
try:
    lastUrl = urlDatabase.all()[-1] # errors if database is empty
    count = lastUrl['intId'] + 1
except:
    print("urlDatabase is empty.")

def getRandomString(length):
    letters = string.ascii_lowercase + string.ascii_uppercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

# injects a 
def render_template_session(file,**kwargs):

    userObj = {
        'isLoggedIn':False,
        'username':""
    }

    if 'sessionId' in request.cookies:
        sessionId = request.cookies.get('sessionId')
        User = Query()
        user = userDatabase.get(User.sessionId == sessionId)
        print(user)
        if user:
            userObj['isLoggedIn'] = True
            userObj['username'] = user['username']
    
    kwargs['user'] = userObj
    return render_template(file, **kwargs)

@app.route("/")
def home():
    return render_template_session("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username and password:
            User = Query()
            userExists = userDatabase.get(User.username == username)
            if userExists:
                return render_template_session("register.html")
            else:
                hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()

                sessionId = getRandomString(256)
                # make this token the required token for verifying their account

                userDatabase.insert({
                    'username':username,
                    'password':hashed,
                    'sessionId':sessionId
                }) 

                # using this manual redirect template due to weirdness with flask redirects.
                r = make_response(render_template("redirect.html",redirect="/"))
                # tells the user to create this cookie for verifying their account
                r.headers.set('Set-Cookie','sessionId='+sessionId+"; Max-Age=20000000")
                return r
    else:
        return render_template_session('register.html')

@app.route("/login",methods=['GET',"POST"])
def login():
    if request.method == "GET":
        return render_template_session("login.html")
    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username and password:
            User = Query()
            userExists = userDatabase.get(User.username == username)
            if userExists:
                hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
                if userExists['password'] == hashed:
                    sessionId = getRandomString(256)
                    # make this token the required token for verifying their account
                    User = Query()
                    userDatabase.update({'sessionId':sessionId}, User.username == username)
                    # using this manual redirect template due to weirdness with flask redirects.
                    r = make_response(render_template("redirect.html",redirect="/"))
                    # tells the user to create this cookie for verifying their account
                    r.headers.set('Set-Cookie','sessionId='+sessionId+"; Max-Age=20000000")
                    return r
                else:
                    return render_template_session("login.html", err="Password is invalid.")
            else:
                return render_template_session("login.html", err="Username does not exist.")

@app.route("/logout", methods=["GET"])
def logout():     
    if 'sessionId' in request.cookies:       
        User = Query()
        sessionId = request.cookies.get('sessionId')
        userDatabase.update({'sessionId':None}, User.sessionId == sessionId)
    return render_template("redirect.html",redirect="/")
# create a url api
@app.route("/createshort", methods=["POST"])
def createshort():
    global count
    url = request.form["url"]
    validUrl = httpPattern.match(url) is not None
    print("ok")
    # url is not a valid browser url
    if not validUrl:
        return render_template_session("index.html",err="Url is not valid")
    
    # generates an id by converting an integer to bytes then base64 encoding it.
    id = base64.b64encode(count.to_bytes((max(count.bit_length(), 1) + 7) // 8,'big')).decode('ascii')
    # url encoding the base64
    id = id.replace("+","_").replace(".","-").replace("=","")
    
    owner = ""
    if 'sessionId' in request.cookies:
        User = Query()
        user = userDatabase.get(User.sessionId == request.cookies.get("sessionId"))
        owner = user["username"]
    # adds the id to the database
    urlDatabase.insert({'url':url,'id':id,'intId':count,'owner':owner})
    count += 1

    # render the page with the generated url.
    return render_template_session("index.html",newUrl = siteDomain +"s/"+ id)
    #return redirect(url_for('home', newUrl = siteDomain +"s/"+ id))
# route to catch all ids
@app.route("/s/<id>", methods=["GET"])
def loadshorturl(id):

    Url = Query()
    result = urlDatabase.get(Url.id == id)

    # url does not exists in the database
    if result == None:
        return render_template_session("index.html", err="ID is not valid")

    ua = parse(request.headers.get('User-Agent'))
    redirectDatabase.insert({
        'id':id,
        'timestamp':round(time.time()*1000),
        'ip':request.remote_addr,
        'device':{'isMobile':ua.is_mobile,'isPc':ua.is_pc,'string':str(ua)}
    })

    # redirects to the url associated with the ID
    return redirect(result['url'])


if __name__ == "__main__":
    app.run()
