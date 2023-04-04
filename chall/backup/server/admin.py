from flask import Blueprint, session, redirect, render_template, request, abort, url_for
from os import urandom
from datetime import timedelta, datetime, timezone

from config import SESSION_DURATION, ADMIN_TBS_STRING, MUSIG2_PUBKEY
import musig2
import smart_contract

admin_page = Blueprint("admin_page", __name__, template_folder="admin_templates")

# Expiration of admin session

@admin_page.before_request
def check_session_expired():
    start = session.get("admin_session_start")
    if start is None:
        return

    now = datetime.now(timezone.utc)

    if (now - start) > timedelta(minutes=SESSION_DURATION):
        session.clear()

# Login

def go_to_login():
    return redirect(url_for("admin_page.login_get"), code=303)

@admin_page.route("/login", methods=["GET"])
def login_get():
    # Already logged in?
    if session.get("admin_authorized"):
        return redirect(url_for("admin_page.admin_get"), code=302)

    # Init session
    session["admin_session_start"] = datetime.now(timezone.utc)
    session["admin_authorized"] = False

    # Construct TBS
    nonce = urandom(16)
    to_be_signed = ADMIN_TBS_STRING.format(duration=SESSION_DURATION, now=session["admin_session_start"], nonce=nonce.hex())
    session["admin_tbs"] = to_be_signed

    return render_template("admin_templates/login.html", pubkey=MUSIG2_PUBKEY, tbs=to_be_signed)

@admin_page.route("/login", methods=["POST"])
def login_post():
    Rx = request.form.get("Rx")
    Ry = request.form.get("Ry")
    s = request.form.get("s")

    try:
        Rx = int(Rx, 16)
        Ry = int(Ry, 16)
        s = int(s, 16)
    except:
        return go_to_login()

    tbs = session.get("admin_tbs")
    if tbs is None:
        return go_to_login()

    if not musig2.verify(tbs, ((Rx, Ry), s)):
        return go_to_login()

    # Login success
    session["admin_authorized"] = True
    return redirect("/achat/redeem", code=303)
