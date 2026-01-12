import os
import time
import pymysql
from flask import Flask, redirect, render_template, render_template_string, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MYSQL_HOST = "127.0.0.1"
MYSQL_PORT = 3306
MYSQL_USER = "ctf"
MYSQL_PASSWORD = "ctf"
MYSQL_DATABASE = "ctf"

app = Flask(__name__)
app.secret_key = os.urandom(24)


def get_db_connection():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        autocommit=True,
    )


def ensure_db() -> None:
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL
                )
                """
            )
            cur.execute("SELECT 1 FROM users WHERE username = %s", ("test",))
            exists = cur.fetchone()
            if not exists:
                cur.execute(
                    "INSERT INTO users (username, password) VALUES (%s, %s)",
                    ("test", "test"),
                )
    finally:
        conn.close()

def waf(value: str) -> bool:
    blacklist = ["'", '"']
    return any(char in value for char in blacklist)


@app.get("/")
def index():
    return render_template("login.html")


@app.post("/login")
def login():

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if waf(username) or waf(password):
        return render_template(
            "login.html",
            error="No quotes allowed!",
            username=username,
        )
    query = (
        "SELECT username, password FROM users "
        f"WHERE username = ('{username}') AND password = ('{password}')"
    )
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
    except pymysql.MySQLError:
        return render_template(
            "login.html",
            error=f"Invalid credentials.",
            username=username,
        )
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if not row:
        return render_template(
            "login.html",
            error="Invalid credentials.",
            username=username,
        )
    if not username == row[0] or not password == row[1]:
        return render_template(
            "login.html",
            error="Invalid credentials.",
            username=username,
        )
    session["user"] = row[0]
    return redirect(url_for("home"))


@app.get("/home")
def home():
    if not session.get("user"):
        return redirect(url_for("index"))
    return render_template_string(open("templates/home.html").read() % session["user"])


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    ensure_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
