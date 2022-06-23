from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, flash, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey
import validators
import string
import random
from sqlalchemy.orm import validates
from flask_login import login_user, login_required, logout_user, current_user, UserMixin, LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///urls.db'
app.config['SECRET_KEY'] = "python flask"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


def generate_link():
    new_link = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return new_link


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


class Urls(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_link = db.Column(db.String(200))
    short_link = db.Column(db.String(100), default=generate_link, unique=True)
    created_on = db.Column(DateTime(timezone=True), default=datetime.utcnow)
    created_by = db.Column(db.Integer, ForeignKey(Users.id))

    @validates('original_link')
    def abc(self, key, original_link):
        if not original_link:
            raise AssertionError('No original link provided')
        if not validators.url(value=original_link):
            raise AssertionError('Provided string is not an url')
        return original_link

    def __init__(self, original_link, created_by):
        self.original_link = original_link
        self.created_by = created_by


@app.route('/')
def signup():
    return render_template('signup.html')


@app.route('/', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = Users.query.filter_by(email=email).first()

    if user:
        flash('Email address already exists')
        return redirect('/')

    new_user = Users(email=email, name=name, password=generate_password_hash(password, method='sha256'))
    db.session.add(new_user)
    db.session.commit()

    return redirect('/login')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = Users.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect('/login')
    login_user(user, remember=remember)
    return redirect('/url/app')


@app.route('/logout/app')
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/list/app')
@login_required
def link_list():
    listall = Urls.query.filter(Urls.created_by == current_user.id).all()
    print(listall)
    return render_template("list.html", query=listall)


@app.route('/search/app', methods=['GET', 'POST'])
@login_required
def look_for():
    if request.method == "POST":
        user_link = Urls.query.filter(Urls.short_link == request.form['short_link']).first()
        return render_template("search.html", user_link=user_link, result=True)
    return render_template("search.html", result=False)


@app.route('/<short_link>')
def redirect_url(short_link):
    link = Urls.query.filter_by(short_link=short_link).first()
    if link:
        return redirect(link.original_link)
    else:
        flash('Invalid URL')


@app.route('/url/app', methods=['GET', 'POST'])
@login_required
def shortlink():
    if request.method == 'POST':
        if not request.form['original_link']:
            flash('Please enter all the fields', 'error')

        else:
            input_url = request.form['original_link']
            try:
                orl = Urls(original_link=input_url, created_by=current_user.id)
                db.session.add(orl)
                db.session.commit()
                listall = Urls.query.filter(Urls.created_by == current_user.id).order_by(Urls.created_on.desc()).limit(5).all()
                return render_template('url.html', url_=orl, result=True, five_link=listall)
            except AssertionError:
                flash('Enter a Valid Url')
    listall = Urls.query.filter(Urls.created_by == current_user.id).order_by(Urls.created_on.desc()).limit(5).all()
    return render_template("url.html", result=False, five_link=listall)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('login.html')


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)