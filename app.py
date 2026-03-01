from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError
import re
import logging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'weqrg9ph43#$^YTwdfggdfsg3r4'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@login_manager.user_loader
def load_user(user_id):
    return Account.query.get(int(user_id))


class Account(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)

    # Failure tracking for lockout
    failed_count = db.Column(db.Integer, default=0, nullable=False)
    last_failed_at = db.Column(db.DateTime, nullable=True)
    lock_expires_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, plaintext: str):
        hashed = bcrypt.generate_password_hash(plaintext)
        # store as utf-8 string
        self.password_hash = hashed.decode('utf-8')

    def verify_password(self, plaintext: str) -> bool:
        if not self.password_hash:
            return False
        try:
            return bcrypt.check_password_hash(self.password_hash, plaintext)
        except ValueError:
            # In case stored hash is incompatible
            return False

    def is_locked(self) -> bool:
        if self.lock_expires_at and datetime.utcnow() < self.lock_expires_at:
            return True
        return False

    def register_failure(self, max_attempts: int = 5, window_minutes: int = 10, lock_minutes: int = 15):
        """
        Sliding window failure counter:
        - If the last failure was older than window_minutes, reset counter.
        - Increment failed_count, and if >= max_attempts, set lock_expires_at.
        """
        now = datetime.utcnow()
        if self.last_failed_at is None or (now - self.last_failed_at) > timedelta(minutes=window_minutes):
            self.failed_count = 1
        else:
            self.failed_count += 1
        self.last_failed_at = now

        if self.failed_count >= max_attempts:
            self.lock_expires_at = now + timedelta(minutes=lock_minutes)
            self.failed_count = 0  # reset after lock

    def reset_failures(self):
        self.failed_count = 0
        self.last_failed_at = None
        self.lock_expires_at = None


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=128)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Create account')

    def validate_username(self, field):
        if Account.query.filter_by(username=field.data).first():
            raise ValidationError("Username already registered.")

    def validate_password(self, field):
        ok, msg = check_password_policy(field.data)
        if not ok:
            raise ValidationError(msg)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder": "Username"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=128)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Sign in')


def check_password_policy(pwd: str):
    """
    Server-side password policy:
    - Minimum length 8
    - Must contain lowercase, uppercase and a digit
    - Recommend (but do not require) a symbol
    Returns (bool, message)
    """
    if not pwd or len(pwd) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[a-z]', pwd):
        return False, "Password must include a lowercase letter."
    if not re.search(r'[A-Z]', pwd):
        return False, "Password must include an uppercase letter."
    if not re.search(r'\d', pwd):
        return False, "Password must include a digit."
    return True, "OK"


class AuthManager:
    """
    Small central place for auth-related DB operations.
    """

    @staticmethod
    def create_account(username: str, password: str, role: str = 'user'):
        acct = Account(username=username, role=role)
        acct.set_password(password)
        db.session.add(acct)
        db.session.commit()
        return acct

    @staticmethod
    def find_by_username(username: str):
        return Account.query.filter_by(username=username).first()

    @staticmethod
    def authenticate(username: str, password: str, max_attempts: int = 5, window_minutes: int = 10, lock_minutes: int = 15):
        acct = AuthManager.find_by_username(username)
        if not acct:
            return False, "Invalid username or password.", None
        if acct.is_locked():
            # compute minutes remaining
            remaining = int((acct.lock_expires_at - datetime.utcnow()).total_seconds() / 60) + 1
            return False, f"Account locked. Try again in {remaining} minute(s).", acct
        if acct.verify_password(password):
            try:
                acct.reset_failures()
                db.session.add(acct)
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
            return True, "Login successful.", acct
        else:
            try:
                acct.register_failure(max_attempts=max_attempts, window_minutes=window_minutes, lock_minutes=lock_minutes)
                db.session.add(acct)
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()
            return False, "Invalid username or password.", acct


# Replace the decorator-based initialization with an explicit startup DB creation.
def ensure_db():
    try:
        # Create tables inside an application context so this works at import/startup
        with app.app_context():
            db.create_all()
    except Exception:
        logger.exception("Unable to create DB tables")


# Ensure DB tables exist when the module is loaded (avoids relying on before_first_request)
ensure_db()


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            AuthManager.create_account(form.username.data.strip(), form.password.data)
            flash("Account created. Please sign in.", "success")
            return redirect(url_for('login'))
        except SQLAlchemyError:
            db.session.rollback()
            flash("Unable to create account at the moment. Try a different username.", "danger")
        except Exception:
            flash("Internal error. Please try again.", "danger")
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        ok, message, acct = AuthManager.authenticate(form.username.data.strip(), form.password.data)
        if ok and acct:
            login_user(acct)
            flash("Welcome back!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash(message, "warning")
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)