from flask import Flask
from repository.database import init_db, db_session
from model.models import User
import os

init_db()

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

@app.route("/adduser/<user>")
def add_user(user):
    u = User(user, f'{user}@localhost')
    db_session.add(u)
    db_session.commit()
    return "success"

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))