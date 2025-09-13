from flask import Flask, render_template, redirect, request
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
Scss(app)

@app.route("/")
def home():
    return render_template('index.html')

if (__name__ in "__main__"):
    app.run(debug=True)