from flask import Blueprint, render_template, request, flash, redirect, url_for, send_from_directory
from .models import Article, Music, User, Vote
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import extract
from datetime import datetime
import json
import requests
import os
from oauthlib.oauth2 import WebApplicationClient
from markdown import markdown
auth = Blueprint('auth', __name__)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

client = WebApplicationClient(GOOGLE_CLIENT_ID)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@auth.route('/')
def index():
    top_votes = db.session.query(Music, db.func.count(Vote.music_id)).filter(Music.release >= '2021-01-01').join(
        Vote, isouter=True).group_by(Music.id).order_by(db.func.count(Vote.music_id).desc()).limit(10).all()
    articles = db.session.query(Article, User.username).join(
        User, isouter=True).group_by(Article.id).limit(5).all()
    return render_template("index.html", data=top_votes, articles=articles)


@auth.route('/assets/<path:path>')
def send_report(path):
    return send_from_directory('assets', path)

# Music Section


@auth.route('/music')
def music():
    musics = Music.query.all()
    return render_template("music.html", items=musics)


@auth.route('/music/<id>')
def view_music(id):
    music = Music.query.filter_by(id=id).first()
    music_canvote = Music.query.filter_by(id=id).filter(
        Music.release >= '2021-01-01').count()
    return render_template("view_music.html", item=music, music_canvote=music_canvote)

# Login Session


@auth.route('/login', methods=["GET", "POST"])
def login():
    if (request.method == "POST"):
        email = request.form.get('email')
        password = request.form.get('password')
        print(email)
        user = User.query.filter_by(email=email).first()
        if user:
            if (check_password_hash(user.password, password)):
                flash("Login Successfully!", category='success')

                login_user(user, remember=True)

                return redirect(url_for('auth.index'))
            else:
                flash("Incorrect password", category='error')
        else:
            flash("Email does not exist.", category='error')
    return render_template("login.html")


@auth.route("/login/google")
def login_google():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri="https://localhost:5000/login/callback",
        scope=["email", "profile"],
    )
    return redirect(request_uri)


@auth.route("/login/callback")
def callback():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    client.parse_request_body_response(json.dumps(token_response.json()))
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
        user_query = User.query.filter_by(email=users_email)
        if (user_query.count() == 0):
            return redirect(url_for("auth.register", google_auth=json.dumps({"google_id": unique_id, "email": users_email, "username": users_name})))
        else:
            if (user_query.first().google_id == None):
                flash("Link With Email Success!", category='success')
                user_query.first().google_id = unique_id
                db.session.commit()
            else:
                flash("Login Successfully!", category='success')
            login_user(user_query.first(), remember=True)
            return redirect(url_for('auth.index'))
    else:
        flash("User email not available or not verified by Google.", category='error')
        return redirect(url_for("auth.login"))


@auth.route('/logout')
def logout():
    logout_user()
    flash("Logout Successfully!", category='success')
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=["GET", "POST"])
def register():
    if (request.method == "POST"):
        google_id = request.form.get('google_id')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(username) < 4:
            flash('Username must be greater than 3 characters.', category='error')
        elif password != password2:
            flash("Password don't match.", category='error')
        elif len(password) < 7:
            flash("Passwords must be at least 7 characters.", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(
                password, method='sha256'), google_id=google_id)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created!.", category='success')
            login_user(new_user, remember=True)
            return redirect(url_for('auth.index'))
    if (request.args.get('google_auth') != None):
        return render_template("register.html", google_auth=json.loads(request.args.get('google_auth')))
    else:
        return render_template("register.html", google_auth=None)


# Vote Section


@login_required
@auth.route('/vote')
def vote():
    notes = db.session.query(Music, db.func.count(Vote.music_id)).filter(
        Music.release >= '2021-01-01').join(Vote, isouter=True).group_by(Music.id).order_by(Music.title).all()
    # notes = Music.query.join(Vote, Music.id==Vote.music_id).filter(Music.release >= '2021-01-01').all()
    return render_template("vote.html", data=notes)


@login_required
@auth.route('/vote/<id>')
def vote_create(id):
    if (Vote.query.filter_by(user_id=current_user.id).filter(extract('month', Vote.date) >= datetime.utcnow().month,
                                                             extract(
                                                                 'year', Vote.date) >= datetime.utcnow().year,
                                                             extract('day', Vote.date) >= datetime.utcnow().day).count() == 0):
        new_vote = Vote(user_id=current_user.id, music_id=id)
        db.session.add(new_vote)
        db.session.commit()
        flash("Vote Successfully!", category='success')
    else:
        flash("You Vote Already Today!", category='error')

    return redirect(url_for('auth.vote'))

# Search


@auth.route('/search')
def search():
    q = request.args.get("q")
    search_result = Music.query.filter(Music.title.like("%{}%".format(q)) | Music.album.like(
        "%{}%".format(q)) | Music.artist.like("%{}%".format(q))).all()
    return render_template("search.html", items=search_result)

# Articles


@auth.route('/article')
def article():
    articles = db.session.query(Article, User.username).join(
        User, isouter=True).group_by(Article.id).limit(5).all()
    return render_template("article.html", articles=articles)


@auth.route('/article/<id>')
def article_read(id):
    article = Article.query.filter_by(id=id).first()
    post_by = User.query.filter_by(id=article.user_id).first().username
    return render_template("view_article.html", post=article, post_by=post_by, description=markdown(article.description))


@auth.route('/article/new', methods=["GET", "POST"])
def new_post():
    if (current_user.role == "Admin" or current_user.role == "Writer"):
        if (request.method == "POST"):
            title = request.form.get('title')
            note = request.form.get('note')
            image_url = request.form.get('image_url')
            new_article = Article(
                title=title, description=note, image_url=image_url, user_id=current_user.id)
            db.session.add(new_article)
            db.session.commit()
            flash("Post Complete!", category='success')
            return redirect(url_for("auth.index"))
        else:
            return render_template("new_post.html")
    else:
        flash("Access Denied.", category='error')
        return redirect(url_for('auth.index'))

# Admin


@login_required
@auth.route('/admin')
def admin():
    if (current_user.role == "Admin"):
        all_user = User.query.all()
        return render_template("admin.html", users=all_user)
    else:
        flash("Access Denied.", category='error')
        return redirect(url_for('auth.index'))


@login_required
@auth.route('/admin/add_user', methods=["POST"])
def add_user():
    if (current_user.role == "Admin"):
        id = request.form['id']
        user = User.query.filter_by(id=id).first()
        user.username = request.form['username']
        user.email = request.form['email']
        user.role = request.form['role']
        db.session.commit()
        flash("Complete", category='success')
        return redirect(url_for('auth.admin'))
    else:
        flash("Access Denied.", category='error')
        return redirect(url_for('auth.index'))


@auth.route('/music/new', methods=["GET", "POST"])
def new_music():
    if (current_user.role == "Admin"):
        if (request.method == "POST"):
            title = request.form.get('title')
            artist = request.form.get('artist')
            album = request.form.get('album')
            artwork = request.form.get('artwork')
            youtube_link = request.form.get('youtube_link')
            spotify_link = request.form.get('spotify_link')
            joox_link = request.form.get('joox_link')
            release = datetime.strptime(request.form.get('release'),"%Y-%m-%d")
            new_music = Music(title=title, artist=artist, album=album, artwork=artwork,
                              youtube_link=youtube_link, spotify_link=spotify_link, joox_link=joox_link, release=release)
            db.session.add(new_music)
            db.session.commit()
            flash("Add Music Complete!", category='success')
            return redirect(url_for("auth.music"))
        else:
            return render_template("new_music.html")
    else:
        flash("Access Denied.", category='error')
        return redirect(url_for('auth.index'))

