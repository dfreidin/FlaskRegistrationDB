from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import MySQLConnector
import md5
import os, binascii
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z-]+$')
app = Flask(__name__)
app.secret_key = "swordfish"
mysql = MySQLConnector(app, "userinfo1")
@app.route('/')
def index():
    return render_template('index.html')
@app.route("/register", methods=["POST"])
def register():
    fn = request.form["first_name"]
    ln = request.form["last_name"]
    em = request.form["email"]
    pw = request.form["password"]
    pc = request.form["confirm_password"]
    valid = True
    if len(fn) < 2:
        flash("Must be at least 2 characters", "first_name")
        valid = False
    if not NAME_REGEX.match(fn):
        flash("Must be letters only", "first_name")
        valid = False
    if len(ln) < 2:
        flash("Must be at least 2 characters", "last_name")
        valid = False
    if not NAME_REGEX.match(ln):
        flash("Must be letters only", "last_name")
        valid = False
    if not EMAIL_REGEX.match(em):
        flash("Not a valid email address", "email")
        valid = False
    if len(pw) < 8:
        flash("Password must be at least 8 characters", "password")
        valid = False
    if pw != pc:
        flash("Password does not match", "confirm_password")
        valid = False
    if not valid:
        return redirect("/")
    salt = binascii.b2a_hex(os.urandom(15))
    hashed_pw = md5.new(pw + salt).hexdigest()
    query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at, updated_at) VALUES(:fn, :ln, :em, :pw, :salt, NOW(), NOW());"
    query_data = {"fn": fn, "ln": ln, "em": em, "pw": hashed_pw, "salt": salt}
    mysql.query_db(query, query_data)
    query = "SELECT id FROM users WHERE email = :em;"
    query_data = {"em": em}
    row = mysql.query_db(query, query_data)
    session["user_id"] = row[0]["id"]
    return redirect("/user")
@app.route("/login", methods=["POST"])
def login():
    em = request.form["email"]
    pw = request.form["password"]
    if not EMAIL_REGEX.match(em):
        flash("Not a valid email address", "login")
        return redirect("/")
    query = "SELECT id, password, salt FROM users WHERE email = :em;"
    query_data = {"em": em}
    user_data = mysql.query_db(query, query_data)
    if len(user_data) != 0 and user_data[0]["password"] == md5.new(pw + user_data[0]["salt"]).hexdigest():
        session["user_id"] = user_data[0]["id"]
        return redirect("/user")
    else:
        flash("Login failed", "login")
        return redirect("/")
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id")
    return redirect("/")
@app.route("/user")
def user():
    if not session.get("user_id"):
        flash("Not logged in", "login")
        return redirect("/")
    query = "SELEcT first_name, last_name, email, created_at FROM users WHERE id = :id;"
    query_data = {"id": session["user_id"]}
    user_data = mysql.query_db(query, query_data)
    return render_template("user.html", user=user_data[0])
app.run(debug=True)