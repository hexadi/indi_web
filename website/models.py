from . import db
from sqlalchemy.sql import func
from flask_login import UserMixin


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    username = db.Column(db.String(150))
    google_id = db.Column(db.String(150))
    role = db.Column(db.String(150),default="User")


class Music(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    album = db.Column(db.String(100))
    artist = db.Column(db.String(100))
    artwork = db.Column(db.String(100))
    youtube_link = db.Column(db.String(100))
    spotify_link = db.Column(db.String(100))
    joox_link = db.Column(db.String(100))
    release = db.Column(db.DateTime(timezone=True), default=func.now())


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    music_id = db.Column(db.Integer, db.ForeignKey('music.id'))
    date = db.Column(db.DateTime(timezone=True), default=func.now())


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    image_url = db.Column(db.String(150))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
