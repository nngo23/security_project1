import hashlib
import pickle
import base64
import logging
import urllib.request

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

from .models import Post, NetworkTrace

# FLAW 1 — A07: Identification and authentication failures
# The registration form imposes no password requirements
# whatsoever — single character passwords are accepted.
def new_account(req):
    if req.method == "POST":
        nick = req.POST.get("username")
        key  = req.POST.get("password")

        # FLAW 1: key is stored without any strength check
        member = User.objects.create_user(username=nick, password=key)
        login(req, member)
        return redirect("board")

        # FIX 1: reject weak passwords before creating the account
        # import re
        # issues = []
        # if len(key) < 8:
        #     issues.append("8 or more characters")
        # if not re.search(r'[A-Z]', key):
        #     issues.append("one uppercase letter")
        # if not re.search(r'[0-9]', key):
        #     issues.append("one number")
        # if issues:
        #    note = "Your password needs: " + ", ".join(issues) + "."
        #   return render(req, "secureapp/new_account.html", {"error": note})
        # member = User.objects.create_user(username=nick, password=key)
        # login(req, member)
        # return redirect("board")

    return render(req, "secureapp/new_account.html")


def sign_in(req):
    if req.method == "POST":
        nick = req.POST.get("username")
        key  = req.POST.get("password")
        found = authenticate(req, username=nick, password=key)
        if found:
            login(req, found)
            return redirect("board")
        return render(req, "secureapp/sign_in.html",
                      {"error": "Username or password is incorrect."})
    return render(req, "secureapp/sign_in.html")


def sign_out(req):
    logout(req)
    return redirect("sign_in")


# FLAW 2 — A08: Software and data integrity failures
# The server accepts base64 input from the user, decodes it, 
# and passes the result to pickle.loads without inspection.
# A crafted payload can silently run commands on the server.
@login_required
def push_post(req):
    if req.method == "POST":
        chunk = req.POST.get("data", "")

        # FLAW 2: attacker-controlled pickle bytes execute on the server
        raw = base64.b64decode(chunk)
        item = pickle.loads(raw)
        Post.objects.create(creator=req.user, message=str(item))
        return redirect("board")

        # FIX 2: use json.loads — parses structure, never runs code
        # import json
        # try:
        #  item = json.loads(chunk)
        #   body = item.get("message", "")
        # except (json.JSONDecodeError, AttributeError):
        #   return HttpResponse("Data format not supported.", status=400)
        # Post.objects.create(creator=req.user, message=body)
        # return redirect("board")

    return render(req, "secureapp/push_post.html")

# FLAW 3 — A09: Security logging and monitoring failures
# Failed login attempts are silently dropped with no record,
# allowing attackers to guess passwords undetected.

# Uncomment when activating the Flaw 3 fix
# breach_log = logging.getLogger(__name__)

def sign_in_muted(req):
    if req.method == "POST":
        nick = req.POST.get("username")
        key  = req.POST.get("password")
        found = authenticate(req, username=nick, password=key)
        if found:
            login(req, found)
            return redirect("board")

        # FLAW 3: failure is shown to the user but written nowhere
        return render(req, "secureapp/sign_in.html",
        {"error": "Username or password is incorrect."})

        # FIX 3: log the failed attempt with the username and caller IP
        # breach_log.warning(
        #    "Failed attempt | user: %s | caller: %s",
        #    nick,
        #    req.META.get("REMOTE_ADDR", "unavailable"),
        #)
        # return render(req, "secureapp/sign_in.html",
        #    {"error": "Username or password is incorrect."})

    return render(req, "secureapp/sign_in.html")

# FLAW 4 — A10: Server-side request forgery (SSRF)
# The server fetches any URL submitted by the user including
# cloud metadata services and private network addresses.
@login_required
def pull_url(req):
    body = ""
    if req.method == "POST":
        link = req.POST.get("url", "")

        # FLAW 4: link is passed straight to urlopen with no filtering
        try:
            with urllib.request.urlopen(link, timeout=3) as r:
                body = r.read(500).decode("utf-8", errors="replace")
        except Exception as e:
          body = f"Request error: {e}"

        NetworkTrace.objects.create(
          address=link,
           excerpt=body[:200]
        )

        # FIX 4: allow only hostnames from a pre-approved set
        # from urllib.parse import urlparse
        # WHITELIST = {"example.com", "api.example.com"}
        # h = urlparse(link).hostname
        # if h not in WHITELIST:
        #    body = "Refused: destination host is not permitted"
        # else:
        #    try:
        #       with urllib.request.urlopen(link, timeout=3) as r:
        #           body = r.read(500).decode("utf-8", errors="replace")
        #    except Exception as e:
        #        body = f"Request error: {e}"
        # NetworkTrace.objects.create(address=link, excerpt=body[:200])

    return render(req, "secureapp/pull_url.html", {"body": body})

# FLAW 5 — A06: Vulnerable and outdated components
# Passwords are hashed with MD5 and stored as plain hex,
# bypassing Django's secure PBKDF2+SHA256 hasher entirely
def new_account_old(req):
    if req.method == "POST":
        nick = req.POST.get("username")
        key  = req.POST.get("password")

        # FLAW 5: unsalted MD5 is trivially cracked
        stale_hash = hashlib.md5(key.encode()).hexdigest()
        member = User(username=nick)
        member.password = stale_hash
        member.save()
        return redirect("sign_in")

        # FIX 5: hand off to create_user for proper modern hashing
        # member = User.objects.create_user(username=nick, password=key)
        # return redirect("sign_in")

    return render(req, "secureapp/new_account_old.html")

# Board_main page
@login_required
def board(req):
    feed = Post.objects.filter(creator=req.user)
    return render(req, "secureapp/board.html", {"feed": feed})
