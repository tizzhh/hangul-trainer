from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import os

#apology, login_required, after request, login & logout functions have been borrowed from finance

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///korean.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get("username") or request.form.get("username") == None:
            return apology("must provide username", 400)

        elif not request.form.get("password") or request.form.get("password") == None:
            return apology("must provide password", 400)

        elif not request.form.get("confirmation") or request.form.get("confirmation") == None:
            return apology("must confirm password", 400)

        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords don't match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) != 0:
            return apology("username already taken", 400)

        password = request.form.get("password")
        countl = 0 #count number of letters
        countn = 0 #count number of numbers
        counts = 0 #count number of symbols
        for i in password:
            if(i.isalpha()):
                countl += 1
            elif(i.isnumeric()):
                countn += 1
            else:
                counts += 1

        if countl < 3 or countn < 3 or counts < 1:
            return apology("password doesn't satisfy requirements :(", 400)


        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/passchange", methods=["POST", "GET"])
def passchange():
    if request.method == "POST":

        if not request.form.get("username") or request.form.get("username") == None:
            return apology("must provide username", 400)

        elif not request.form.get("password") or request.form.get("password") == None:
            return apology("must provide previous password", 400)

        elif not request.form.get("confirmation") or request.form.get("confirmation") == None:
            return apology("must provide new password", 400)

        password = db.execute("SELECT hash FROM users WHERE username = ?", request.form.get("username"))[0]["hash"]
        if check_password_hash(password, request.form.get("password")):
            db.execute("UPDATE users SET hash = ? WHERE username = ?", generate_password_hash(
                       request.form.get("confirmation")), request.form.get("username"))

        else:
            return apology("wrong previous password", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    else:
        return render_template("passchange.html")


@app.route("/train", methods=["POST", "GET"])
@login_required
def train():
    if request.method == "GET":
        return render_template("train.html")
    else:
        return render_template("train.html")


@app.route("/high_score")
@login_required
def high_score():
    high_score = db.execute("SELECT username, high_score FROM users ORDER BY high_score DESC")
    return render_template("high_score.html", high_score=high_score)

@app.route("/record_score", methods=["POST"])
@login_required
def record_score():
    score = int(request.form.get("highscore"))
    high_score = db.execute("SELECT high_score FROM users WHERE id = ?", session["user_id"])[0]["high_score"]
    if score > high_score:
        db.execute("UPDATE users SET high_score = ? WHERE id = ?", score, session["user_id"])
    return redirect("/high_score")