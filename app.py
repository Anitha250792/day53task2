from flask import Flask, render_template, request, redirect, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, PasswordField, validators
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = 'secretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Logger setup for failed logins
logging.basicConfig(filename='login_failures.log', level=logging.INFO)

# Common weak passwords list
weak_passwords = ['password', '12345678', 'admin123', 'qwerty123']

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))  # hashed password only
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)

class RegistrationForm(Form):
    email = StringField('Email', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8, message="Password must be at least 8 characters")
    ])

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        password = form.password.data

        if password.lower() in weak_passwords:
            flash('Weak/common password not allowed!', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Email already exists.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password_input):
                flash('Login successful', 'success')
                return redirect('/')
            else:
                logging.info(f'Failed login attempt for email: {email} at {datetime.utcnow()}')
                flash('Password mismatch', 'danger')
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/')
def home():
    return '<h2>Welcome to the Secure App!</h2><p><a href="/register">Register</a> | <a href="/login">Login</a></p>'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
