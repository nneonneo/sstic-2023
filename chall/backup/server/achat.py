from flask import Blueprint, session, redirect, render_template, request, abort, url_for, send_from_directory
from datetime import timedelta, datetime, timezone
import os

from config import BUY_WINDOW_DURATION
import smart_contract

achat_page = Blueprint("achat_page", __name__,template_folder="achat_templates")
# Ensure contract is deployed at the very beginning
smart_contract.get_contract()

# Expiration of super admin session

@achat_page.before_request
def check_session_expired():
    start = session.get("achat_session_start")
    if start is None:
        return

    now = datetime.now(timezone.utc)

    if (now - start) > timedelta(minutes=BUY_WINDOW_DURATION):
        session["achat_authorized"] = False



# Redeem

def go_to_redeem():
    return redirect(url_for("achat_page.redeem_get"), code=303)

@achat_page.route("/redeem", methods=["GET"])
def redeem_get():
    # Not an admin?
    if not session.get("admin_authorized"):
        return redirect("/admin/login", code=303)

    # Already logged in?
    if session.get("achat_authorized"):
        return redirect(url_for("achat_page.achat_get"), code=302)

    # Init session
    session["achat_session_start"] = datetime.now(timezone.utc)
    session["achat_authorized"] = False

    return render_template("achat_templates/redeem.html")

@achat_page.route("/redeem", methods=["POST"])
def login_post():
    # Not an admin?
    if not session.get("admin_authorized"):
        return redirect("/", code=303)

    # Handle interaction with Starknet contract
    coupon_id = request.form.get("id")
    code = request.form.get("code")
    a = request.form.get("a")
    b = request.form.get("b")

    try:
        # Abort if data is None or not well formated
        coupon_id = int(coupon_id, 16)
        code = [int(i, 16) for i in code.split(',')]
        a = int(a, 16)
        b = int(b, 16)
    except:
        return go_to_redeem()

    if not smart_contract.is_valid(coupon_id, code, a, b):
        return go_to_redeem()

    # Redeem success
    session["achat_authorized"] = True
    return go_to_achat()


# Actual achat page

def go_to_achat():
    return redirect(url_for("achat_page.achat_get"), code=303)

@achat_page.route("/", methods=["GET"])
def achat_get():
    if session.get("achat_authorized") and session.get("admin_authorized"):
        return render_template("achat_templates/success.html")
    else:
        return redirect("/achat/redeem", code=302)

@achat_page.route("/captcha", methods=["GET"])
def captcha_get():
    if session.get("achat_authorized") and session.get("admin_authorized"):
        return send_from_directory(
                "/app/internal/",
                "captcha_6111e1675f3e6386a3b33e9b07f94c08b51c108fab6c77b3cb34ea8701bfb891.tgz")
    else:
        return redirect("/achat/redeem", code=302)

