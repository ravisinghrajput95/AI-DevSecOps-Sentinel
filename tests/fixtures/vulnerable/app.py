# Deliberately vulnerable Python fixture for scanner tests.
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL injection: user input concatenated into the query
    rows = conn.execute("SELECT * FROM users WHERE id = " + user_id).fetchall()
    return {"users": [dict(r) for r in rows]}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection: user input passed to a shell
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output


if __name__ == "__main__":
    # Debug mode exposes the Werkzeug debugger to remote users
    app.run(host="0.0.0.0", debug=True)
