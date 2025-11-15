from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Simple role-based user model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Forms
class RegisterForm(FlaskForm):
    username = StringField('username', validators=[
        DataRequired(), Length(min=3, max=80), Regexp(r'^[A-Za-z0-9_\-]+$', message='Invalid characters')
    ])
    password = PasswordField('password', validators=[DataRequired(), Length(min=6)])


class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('password', validators=[DataRequired()])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Role required decorator
def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                flash('Unauthorized access')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registered, please log in')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in')
            return redirect(url_for('index'))
        flash('Invalid credentials')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out')
    return redirect(url_for('index'))

# A simple search that demonstrates safe parameterized queries
@app.route('/search')
def search():
    q = request.args.get('q', '')
    results = []
    if q:
        # SQLAlchemy will parameterize the value and avoid SQL injection
        results = User.query.filter(User.username.like(f"%{q}%")).all()
    return render_template('search.html', results=results, q=q)

# Admin-only page
@app.route('/admin')
@login_required
@roles_required('admin')
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
