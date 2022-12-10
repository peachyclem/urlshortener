'''
Author: Sareena Finner
Project: Url Shortener
'''

from flask import Flask, redirect, url_for,render_template, request,make_response, json
import re
from tinydb import TinyDB, Query
import time
from user_agents import parse
import string
import random
from datetime import datetime
import traceback

# url Ids are base64 encoding of an incremented integer.
import base64

import hashlib

# regex to check if the string is a url
httpPattern = re.compile("^[a-zA-Z0-9\-]+(\.[a-zA-Z0-9\-]+)+$")
# the url this is hosted on
siteDomain = "http://localhost:5000/"

app = Flask(__name__)

# create the three tables for storing data
urlDatabase = TinyDB('urlDatabase.json')
redirectDatabase = TinyDB('redirectDatabase.json')
userDatabase = TinyDB('userDatabase.json')

# initialize the ID counter to 1
id_counter = 1

# get the last inserted ID from the database
lastUrl = urlDatabase.all()
if len(lastUrl) > 0:
    # increment the ID counter to the next ID in the sequence
    id_counter = lastUrl[-1]['intId']
else:
    print("urlDatabase is empty.")



# Define the time_ago function to display timestamps relative to the current time
def timeAgo(timestamp):
    # Calculate the time difference between now and the timestamp
    time_diff = datetime.now() - datetime.fromtimestamp(timestamp / 1000)

    # Format the time difference as a string
    if time_diff.days:
        time_ago = f"{time_diff.days} days ago"
    elif time_diff.seconds // 3600:
        time_ago = f"{time_diff.seconds // 3600} hours ago"
    elif time_diff.seconds // 60:
        time_ago = f"{time_diff.seconds // 60} minutes ago"
    else:
        time_ago = f"{time_diff.seconds} seconds ago"
    return time_ago

# creates a random string composed of a-z A-Z of n length
def getRandomString(length):
    letters = string.ascii_lowercase + string.ascii_uppercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

# gets the logged in user based on the session id provided by the user.
# returns None if no sessionId matches a user
def getLoggedInUser():
    if 'sessionId' in request.cookies:
        User = Query()
        return userDatabase.get(User.sessionId == request.cookies.get("sessionId"))

# converts a number to a encoded string.
# 1 -> a
# 26 -> z
# 27 -> A
# 52 -> Z
# 53 -> aa
def encodeNumber(num):
    # define the characters we will be using
    characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    # initialize the encoded string
    encoded = ''
    
    # loop until num is 0
    while num > 0:
        # get the remainder of num divided by the number of characters
        remainder = num % len(characters)
        
        # if the remainder is 0, use the last character in the list and decrement num by 1
        if remainder == 0:
            char = characters[-1]
            num -= 1
        else:
            # get the character at the index of the remainder - 1
            char = characters[remainder-1]
        
        # append the character to the encoded string
        encoded = char + encoded
        
        # update num to be the quotient of num divided by the number of characters
        num = num // len(characters)
    
    # return the encoded string
    return encoded


# injects a user object into each template to render out the login state
def render_template_session(file,**kwargs):

    userObj = {
        'isLoggedIn':False,
        'username':""
    }

    user = getLoggedInUser()
    if user:
        userObj['isLoggedIn'] = True
        userObj['username'] = user['username']
    
    kwargs['user'] = userObj
    return render_template(file, **kwargs)

# home page route
@app.route("/")
def home():
    return render_template_session("index.html")

# register page route
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username and password:
            User = Query()
            userExists = userDatabase.get(User.username == username)
            if userExists:
                return render_template_session("register.html",err="Username is taken")
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
                r.headers.set('Set-Cookie','sessionId='+sessionId+"; Max-Age=20000000; Secure")
                return r
        else:
            return render_template_session('register.html', err="Username or password must not be blank")
    else:
        return render_template_session('register.html')

# login page route
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

# logout api route
@app.route("/logout", methods=["GET"])
def logout():     
    if 'sessionId' in request.cookies:       
        User = Query()
        sessionId = request.cookies.get('sessionId')
        userDatabase.update({'sessionId':None}, User.sessionId == sessionId)
    return render_template("redirect.html",redirect="/")

# create shortened api url route
@app.route("/createshort", methods=["POST"])
def createshort():
    global id_counter

    url = request.form["url"]

    # url is not a valid browser url
    if not is_valid_url(url):
        return render_template_session("index.html", err="Url is not valid")

    short_url = encodeNumber(id_counter)
    id_counter += 1

    logged_in_user = getLoggedInUser()
    url_owner = logged_in_user["username"] if logged_in_user else ""

    # adds the id to the database
    urlDatabase.insert({'url': url, 'id': short_url, 'intId': id_counter, 'owner': url_owner})

    # render the page with the generated url.
    return render_template_session("index.html", newUrl="{}s/{}".format(siteDomain, short_url))

# validates if a url is a real url
def is_valid_url(url: str):
    return httpPattern.match(url) is not None


    #return redirect(url_for('home', newUrl = siteDomain +"s/"+ id))
# route to catch all ids
@app.route("/s/<id>", methods=["GET"])
def loadshorturl(id):

    Url = Query()
    result = urlDatabase.get(Url.id == id)
    # url does not exists in the database
    if result == None:
        return render_template_session("index.html", err="ID is not valid")
    
    # only log it if the url the person is visiting is created by a person who was logged in.
    if result['owner'] != '':
        useragent = request.headers.get('User-Agent')
        ua = parse(useragent)
        redirectDatabase.insert({
            'id':id,
            'timestamp':round(time.time()*1000),
            'ip':request.remote_addr,
            'device':{'userAgent':useragent,'isMobile':ua.is_mobile,'isPc':ua.is_pc,'string':str(ua)}
        })

    # redirects to the url associated with the ID
    return redirect('https://'+result['url'])

# dashboard page route
@app.route("/dashboard", methods=["GET"])
def dashboard():

    user = getLoggedInUser()
    # validate they are allowed to view this page
    if user is None:
        return render_template_session("index.html")

    Url = Query()
    urls = list(
        map(
            lambda n:{'id':n["id"],'url':n['url']},
            urlDatabase.search(Url.owner == user['username'])
        )
    )


    return render_template_session("dashboard.html",urls=urls)

#
@app.route("/dashboard/<id>", methods=["GET"])
def dashboardId(id):

    user = getLoggedInUser()
    # validate they are allowed to view this page
    if user is None:
        return render_template_session("index.html")

    Url = Query()
    url = urlDatabase.get(Url.id == id)

    # validate they are the owner of this url id
    if url['owner'] != user['username']:
        return render_template_session("index.html")

    # get the click history
    Redirect = Query()
    clicks = redirectDatabase.search(Redirect.id == id)
    length = len(clicks)
    
    # only show the 20 most recent clicks
    clicks = clicks[-20:]
    clicks.reverse()
    for click in clicks:
        click['time'] = timeAgo(click['timestamp'])
    
    payload = {
        'total': length,
        'recent':clicks
    }

    return render_template_session("dashboardId.html",data=payload)


@app.errorhandler(Exception)
def errorPage(e):



    response = e.get_response()
    errJson = json.dumps({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })

    try:
        if e.code != 404: # 404 errors are very common.
            # Log every error that users encounter on the pages and the traceback.
            with open("log.txt", "a") as f:
                f.write(str(json.dumps({
                    "code":e.code,
                    "description":e.description,
                    "name":e.name,
                    "traceback":"".join(traceback.TracebackException.from_exception(e).format())
                })) + "\n")

    except:
        print("Error while writing to the log file")
    
    # replace the body with JSON
    response.data = errJson
    response.content_type = "application/json"
    return response
if __name__ == "__main__":
    app.run()
