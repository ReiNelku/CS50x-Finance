import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
import time
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Add support for loop control
app.jinja_env.add_extension("jinja2.ext.loopcontrols")

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
    """Show portfolio of stocks"""
    # Query database for user bought shares
    shares = db.execute(
        "SELECT name, SUM(shares) AS shares FROM history WHERE user_id = ? GROUP BY name;",
        session["user_id"],
    )
    # Query database for user cash
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    # Initialize total amount
    total = cash[0]["cash"]

    # Store price and total of each share in a dictionary
    for share in shares:
        stock = lookup(share["name"])
        share["price"] = stock["price"]
        share["total"] = share["shares"] * share["price"]
        total += share["total"]

    return render_template(
        "index.html", shares=shares, cash=cash[0]["cash"], total=total
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # Check if symbol is submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)
        # Check if shares are submitted
        elif not request.form.get("shares"):
            return apology("missing shares", 400)

        # Check if shares are an integer
        if not request.form.get("shares").isnumeric():
            return apology("invalid shares", 400)
        # Check if shares are positive non-zero
        elif int(request.form.get("shares")) < 1:
            return apology("invalid shares", 400)

        # Check if symbol is valid
        if (symbol := lookup(request.form.get("symbol"))) is None:
            return apology("invalid symbol", 400)

        # Calculate the price of the shares
        price = symbol["price"] * int(request.form.get("shares"))

        # Query users database for id
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Check if user can afford shares
        if user[0]["cash"] < price:
            return apology("insufficient funds", 400)

        # Get current time
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Update user cash
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            user[0]["cash"] - price,
            session["user_id"],
        )

        # Store the user transaction in a database
        db.execute(
            "INSERT INTO history (user_id, name, shares, price, transacted) VALUES(?, ?, ?, ?, ?)",
            session["user_id"],
            symbol["name"],
            int(request.form.get("shares")),
            price,
            now,
        )

        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT name, shares, price, transacted FROM history WHERE user_id = ?",
        session["user_id"],
    )
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change user password"""
    if request.method == "POST":
        # Check if current password is submitted
        if not request.form.get("current"):
            return apology("must provide current password", 400)
        # Check if new password is submitted
        elif not request.form.get("new"):
            return apology("must provide new password", 400)
        # Check if password confirmation is submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        # Get current user's password hash
        current_hash = db.execute(
            "SELECT hash FROM users WHERE id = ?", session["user_id"]
        )

        # Check if user has inputed correct password
        if not check_password_hash(
            current_hash[0]["hash"], request.form.get("current")
        ):
            return apology("invalid password", 400)

        # Check if new and old passwords are the same
        if request.form.get("current") == request.form.get("new"):
            return apology("new and old password are the same", 400)

        # Check if new password and password confirmation match
        if not request.form.get("new") == request.form.get("confirmation"):
            return apology("new passwords do not match", 400)

        # Generate hash for new password
        new_hash = generate_password_hash(request.form.get("new"))

        # Update user's new password
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"]
        )

        # Log out user
        session.clear()

        flash("Password Changed!")
        return redirect("/")
    else:
        return render_template("password.html")


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
    """Get stock quote."""
    if request.method == "POST":
        # Check if symbol is submitted
        if not request.form.get("symbol"):
            return apology("missing symbol", 400)

        # Check if symbol is valid
        if (symbol := lookup(request.form.get("symbol"))) is None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Check if username is submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        # Check if password is submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        # Check if password confirmation is submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confimation", 400)

        # Query database for usename
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Check if the username already exists
        if len(rows) != 0:
            return apology("the username already exists", 400)

        # Check if password and password confirmation match
        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Create a new user in the database
        id = db.execute(
            "INSERT INTO users (username, hash) VALUES(?,?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        # Log in with the newly created user
        session["user_id"] = id

        # Redirect user to home page
        return redirect("/")
    else:
        # Render the registration form
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Query database for stocks which the user has bought
    stocks = db.execute(
        "SELECT name AS symbol, SUM(shares) AS shares FROM history WHERE user_id = ? GROUP BY name;",
        session["user_id"],
    )

    # Store each stock's symbol in a list
    symbols = []
    for stock in stocks:
        if not stock["shares"] == 0:
            symbols.append(stock["symbol"])

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        # Get current time
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        # Check if symbol is submitted
        if not symbol:
            return apology("missing symbol", 400)
        # Check if user has bought that stock
        elif symbol not in symbols:
            return apology("symbol not owned", 400)
        # Check for positive non-zero shares
        elif shares < 1:
            return apology("shares must be positive", 400)

        # Check if user has enough stocks to sell
        for stock in stocks:
            if stock["symbol"] == symbol:
                if stock["shares"] < shares:
                    return apology("too many shares", 400)

        # Get user cash balance
        user = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        # Update user cash balance
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            user[0]["cash"] + lookup(symbol)["price"] * shares,
            session["user_id"],
        )

        # Store user transaction in a database
        db.execute(
            "INSERT INTO history (user_id, name, shares, price, transacted) VALUES(?, ?, ?, ?, ?)",
            session["user_id"],
            symbol,
            shares * -1,
            lookup(symbol)["price"] * shares,
            now,
        )

        flash("Sold!")
        return redirect("/")
    else:
        return render_template("sell.html", symbols=symbols)
