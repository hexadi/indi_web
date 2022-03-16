from flask import Blueprint, render_template, request, flash, redirect, url_for, send_from_directory
from .models import Article, Music, User, Vote
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user
auth = Blueprint('auth', __name__)

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


@auth.route('/logout')
def logout():
    logout_user()
    flash("Logout Successfully!", category='success')
    return redirect(url_for('auth.login'))


@auth.route('/register', methods=["GET", "POST"])
def register():
    if (request.method == "POST"):
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
                password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created!.", category='success')
            login_user(new_user, remember=True)
            return redirect(url_for('auth.index'))
    return render_template("register.html", google_auth=None)

# Search


@auth.route('/search')
def search():
    q = request.args.get("q")
    search_result = Music.query.filter(Music.title.like("%{}%".format(q)) | Music.album.like(
        "%{}%".format(q)) | Music.artist.like("%{}%".format(q))).all()
    return render_template("search.html", items=search_result)
