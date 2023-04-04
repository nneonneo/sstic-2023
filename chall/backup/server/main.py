from config import FLASK_SECRET_KEY
from admin import admin_page
from achat import achat_page
from flask_bootstrap import Bootstrap5
from flask import Flask, send_file, render_template, send_from_directory
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.register_blueprint(admin_page, url_prefix="/admin")
app.register_blueprint(achat_page, url_prefix="/achat")

bootstrap = Bootstrap5(app)

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/data_34718ec031bbb6e094075a0c7da32bc5056a57ff082c206e6b70fcc864df09e9.h5", methods=["GET"])
def data_get():
    return send_from_directory(
            "/app/internal/",
            "data_34718ec031bbb6e094075a0c7da32bc5056a57ff082c206e6b70fcc864df09e9.h5")
