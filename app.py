from flask import Flask, render_template, redirect, url_for, flash, request, Blueprint, jsonify
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user



app = Flask(__name__)
# old sqllite db
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/blog'

app.config['SECRET_KEY'] = '1234567890'
#bp = Blueprint('/auth', __name__, url_prefix='/auth')

#app.register_blueprint(bp)

db = SQLAlchemy(app)

migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/login'

@login_manager.user_loader
def load_user(user_id):
    return SignupUser.query.get(int(user_id))

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
    username = StringField('Username', validators=[ DataRequired() ])
    password = PasswordField('Passsword', validators=[ DataRequired() ])
    submit = SubmitField('Sign in')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[ DataRequired() ])
    FirstName = StringField('First Name', validators=[ DataRequired() ])
    LastName = StringField('Last Name', validators=[ DataRequired() ])
    email = StringField('Email', validators=[ DataRequired() ])
    password = PasswordField('Passsword', validators=[ DataRequired(), EqualTo('confirmPassword') ])
    confirmPassword = PasswordField('Confirm Passsword', validators=[ DataRequired() ])
    submit = SubmitField('Sign up')


class SignupUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False, unique=True)
    FirstName = db.Column(db.String(120), nullable=False)
    LastName = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return self.FirstName

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    author = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(120), nullable=False)
    content = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return self.title

class NameForm(FlaskForm):
    """
    A flask form
    """
    name = StringField('whats your name', validators=[ DataRequired() ])
    submit = SubmitField('submit')


@app.route('/', strict_slashes=False)
@login_required
def home():
    posts = BlogPost.query.order_by(BlogPost.id.desc()).all()
    return render_template('home.html', name='home_page', posts=posts)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

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
@login_required
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

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    user = User.query.get_or_404(id)
    form = UserForm()

    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        all_users = User.query.order_by(User.date_created)

        try:
            db.session.commit()
            flash('user updated succcessfully')
            return render_template('user.html', name=user.name, form=form, all_users=all_users)
        except Exception as e:
            flash('user not found')
            return render_template('user.html', name=user.name, form=form, all_users=all_users)
    return render_template('update1.html', user=user, form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = SignupUser.query.filter_by(username=form.username.data).first()

        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash('Logged in successfully')
                return redirect(url_for('home'))
            else:
                flash('Incorrect password')
        else:
            flash('User Doesn\'t Exist')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('logged out succeffully')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['FirstName']
        lastname = request.form['LastName']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conpassword = request.form['confirmPassword']

        new = SignupUser(username=username, FirstName=firstname, LastName=lastname, email=email, password=password)
        db.session.add(new)
        db.session.commit()
        flash('user created successfully')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/dashboard/update/<int:id>', methods=['GET','POST'])
@login_required
def updateUser(id):
    user = SignupUser.query.get_or_404(id)
    form = SignupForm()
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.FirstName = request.form['FirstName']
        user.LastName = request.form['LastName']
        user.email = request.form['email']

        try:
            db.session.commit()
            flash('User updated successfully')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Error!! User not found')
            return redirect(url_for('dashboard'))
    return render_template('update.html', form=form, user=user)

@app.route('/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete(id):
    form = UserForm()
    userToDelete = User.query.get_or_404(id)
    blogToDelete = BlogPost.query.get_or_404(id)

    try:
        db.session.delete(blogToDelete)
        db.session.commit()
        flash('user deleted')
        all_users = User.query.order_by(User.date_created)
        return redirect(url_for('home'))
    except Exception as e:
        flash('No user found')

@app.route('/deleteuser/<int:id>', methods=['GET', 'POST'])
@login_required
def deleteuser(id):
    form = UserForm()
    userToDelete = User.query.get_or_404(id)
    all_users = User.query.order_by(User.date_created)
    try:
        db.session.delete(userToDelete)
        db.session.commit()
        flash('user deleted successfully')
        return render_template('user.html', name='hello', form=form, all_users=all_users)
    except Exception as e:
        flash('user not found')


@app.route('/postdelete/<int:id>', methods=['GET', 'POST'])
def deletepost(id):
    blogToDelete = BlogPost.query.get_or_404(id)

    try:
        db.session.delete(blogToDelete)
        db.session.commit()
        flash('Post deleted successfully')
        return redirect(url_for('home'))
    except Exception as e:
        pass

@app.route('/dict', methods=['GET', 'POST'])
def get_user():
    all = {
            'name': 'richard',
            'lastname': 'oduor',
            'age': 20,
            'gender': 'male',
            'hobbies': ['football', 'music', 'movies'],
            'others': {
                'parents': True,
                'siblings': 4,
                'left': False
                },
            }
    return jsonify(all)

@app.route('/blog', methods=['GET', 'POST'])
@login_required
def blog():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        slug = request.form['slug']
        content = request.form['content']

        post = BlogPost(title=title, author=author, slug=slug, content=content)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('home'))

    return render_template('blog.html')

@app.route('/blog/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    post = BlogPost.query.get_or_404(id)

    if request.method=='POST':
        post.title = request.form['title']
        post.author = request.form['author']
        post.slug = request.form['slug']
        post.content = request.form['content']
        try:
            db.session.commit()
            flash('Post updated successfully')
            return redirect(url_for('home'))
        except Exception as e:
            pass
    return render_template('blog_edit.html', post=post)

@app.errorhandler(404)
def notFound(e):
    return render_template('404.html')
