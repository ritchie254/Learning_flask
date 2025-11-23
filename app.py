from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate



app = Flask(__name__)
# old sqllite db
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/blog'

app.config['SECRET_KEY'] = '1234567890'
#bp = Blueprint('/auth', __name__, url_prefix='/auth')

#app.register_blueprint(bp)

db = SQLAlchemy(app)

migrate = Migrate(app, db)

#for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'Name: {self.name}'

#form fro the user
class UserForm(FlaskForm):
    name = StringField('Name', validators=[ DataRequired() ])
    email = StringField('Email', validators=[ DataRequired() ])
    submit = SubmitField('submit')

class LoginUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return self.email

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[ DataRequired() ])
    password = PasswordField('Passsword', validators=[ DataRequired() ])
    submit = SubmitField('Sign in')

class SignupForm(FlaskForm):
    FirstName = StringField('First Name', validators=[ DataRequired() ])
    LastName = StringField('Last Name', validators=[ DataRequired() ])
    email = StringField('Email', validators=[ DataRequired() ])
    password = PasswordField('Passsword', validators=[ DataRequired(), EqualTo('confirmPassword') ])
    confirmPassword = PasswordField('Confirm Passsword', validators=[ DataRequired() ])
    submit = SubmitField('Sign up')


class SignupUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    FirstName = db.Column(db.String(120), nullable=False)
    LastName = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return self.FirstName + ' ' + self.LastName


class NameForm(FlaskForm):
    """
    A flask form
    """
    name = StringField('whats your name', validators=[ DataRequired() ])
    submit = SubmitField('submit')


@app.route('/', strict_slashes=False)
def home():
    return render_template('index.html', name='home_page')

@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    form = NameForm()

    if form.validate_on_submit():
        name = form.name.data
        form.name.data = ''
        #return redirect(url_for('home'))
        flash('User created successfully')
    return render_template('name.html', name=name, form=form)

@app.route('/user/add', methods=['GET', 'POST'])
def user():
    name = ''
    form = UserForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:
            user = User(name=form.name.data, email=form.email.data)
            db.session.add(user)
            db.session.commit()
        else:
            flash(f'User with email:{form.email.data} already exists')
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        flash('User created succefully')
    all_users = User.query.order_by(User.date_created)
    return render_template('user.html', name=name, form=form, all_users=all_users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        user = LoginUser(email=email, password=password)

        db.session.add(user)
        db.session.commit()
        flash('user logged in  successfully')
        return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if request.method == 'POST':
        firstname = request.form['FirstName']
        lastname = request.form['LastName']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conpassword = request.form['confirmPassword']

        new = SignupUser(FirstName=firstname, LastName=lastname, email=email, password=password)
        db.session.add(new)
        db.session.commit()
        flash('user created successfully')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
    form = UserForm()
    userToDelete = User.query.get_or_404(id)

    try:
        db.session.delete(userToDelete)
        db.session.commit()
        flash('user deleted')
        all_users = User.query.order_by(User.date_created)
        return redirect(url_for('user'))
    except Exception as e:
        flash('No user found')
