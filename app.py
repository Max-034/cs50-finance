import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")




@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():


    ne = db.execute("SELECT symbol, SUM(quantity) AS total_quantity FROM Data WHERE id = ? GROUP BY symbol ORDER BY total_quantity DESC" , session.get('user_id'))
    ne = [n for n in ne if n['total_quantity'] > 0]




    for items in ne:
        items['price'] = float(lookup(items['symbol'])['price'])
        items['holdings'] = float(items['total_quantity'])*float(items['price'])

    """Show portfolio of stocks"""
    return render_template("index.html" , p = ne)


@app.route("/buy", methods=["GET", "POST"])
@login_required

def buy():
    if request.method == "GET":

        return render_template("buy.html")
    else:
        if not request.form.get("symbol") or lookup(request.form.get("symbol")) == "none" or int(request.form.get("shares")) < 1:
            return apology("Error" , 403)
        paehe = db.execute("SELECT cash FROM users WHERE id = ? " , session.get('user_id'))
        if float(paehe[0].get('cash')) >= float(float(request.form.get("shares"))*float(lookup(request.form.get("symbol")).get("price"))):
            nv = db.execute("SELECT username FROM users WHERE id = ? " , session.get('user_id'))
            t = datetime.now()
            db.execute("UPDATE users SET cash = ? WHERE id = ? " , float(paehe[0].get('cash')) - float(request.form.get("shares"))*float(lookup(request.form.get("symbol")).get('price')) , session.get('user_id') )
            db.execute("INSERT INTO Data (username , symbol , quantity , time , price , id) VALUES  (? , ? , ? , ? , ? , ?)" , nv[0].get('username') , request.form.get("symbol") , float(request.form.get("shares")) , t.strftime("%Y-%m-%d %H:%M:%S") , float(lookup(request.form.get("symbol")).get('price')) , session.get('user_id'))
            return redirect("/")

        else:
            return apology("paehe nahi hai bhai itne" , 403)



    """Buy shares of stock"""
    return apology("TODO")


@app.route("/history")
@login_required
def history():
    dta = db.execute("SELECT * FROM Data WHERE id = ? AND quantity > 0 " , session.get('user_id'))
    dtaa = db.execute("SELECT * FROM Data WHERE id = ? AND quantity < 0 " , session.get('user_id'))

    return render_template("history.html" , q = dta , r = dtaa)
    """Show history of transactions"""



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":

        return render_template("quote.html")

    else:
        if request.form.get('symbol'):

            return render_template("quoted.html" , p = lookup(request.form.get("symbol")))
        else:
            return apology("bt" , 400)






    """Get stock quote."""


@app.route("/register", methods=["GET", "POST"])
def register():

    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
         if not request.form.get("username"):
            return apology("must provide username", 400)
         rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
         if len(rows) == 1:
             return apology("Already Exists" , 403)
         if not request.form.get("password") and not request.form.get("confirmation") and request.form.get("password") != request.form.get("confirmation"):
            return apology("PASSWORDS NOT MATCHING", 400)
         username = request.form.get('username')
         password = request.form.get('password')
         hashed_password = generate_password_hash(password, method='pbkdf2', salt_length=16)
         db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)

         return redirect("/login")








@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():

    ne = db.execute("SELECT symbol, SUM(quantity) AS total_quantity FROM Data WHERE id = ? GROUP BY symbol ORDER BY total_quantity DESC" , session.get('user_id'))
    nee = [n for n in ne if n['total_quantity'] > 0]
    a = 0
    t = datetime.now()
    for p in nee:
        if request.form.get('car') == p['symbol']:
            a = p['total_quantity']
        else:
            pass



    if request.method == "POST":
        if int(request.form.get('sell')) > 0 and request.form.get('car') and int(request.form.get('sell')) <= a:


            db.execute("INSERT INTO Data (symbol , quantity , id , price , time) VALUES (? , ? , ? , ? , ?) " , request.form.get('car') , -1 * int(request.form.get('sell')) , session.get('user_id') , lookup(request.form.get('car')).get('price') , t.strftime("%Y-%m-%d %H:%M:%S") )
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ? " , float(request.form.get('sell'))*float(lookup(request.form.get("car")).get('price')) , session.get('user_id'))

            return redirect("/")
        else:
            return apology("kuch toh bt hui hai" , 403)


    else:
        ne = db.execute("SELECT symbol, SUM(quantity) AS total_quantity FROM Data WHERE id = ? GROUP BY symbol ORDER BY total_quantity DESC" , session.get('user_id'))




        return render_template("sell.html" , p = nee)
    """Sell shares of stock"""
    return apology("TODO")
