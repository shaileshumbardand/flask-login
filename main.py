from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, logout_user, LoginManager, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, InputRequired, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)  # initiate database instance
bcrypt = Bcrypt(app)  # To hash password
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"  # connect app file to db
app.config['SECRET_KEY'] = "thisisscretkey"  # secret key used to secure session cookie

login_manager = LoginManager()  # To connect flask with flask_login
login_manager.init_app(app)  # register app
login_manager.login_view = "login"  # register login


# load user initial process
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# database class
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)


# registration form
class RegistrationForm(FlaskForm):
    username = StringField(render_kw={"placeholder": "Username"}, validators=[InputRequired()])
    password = PasswordField(render_kw={"placeholder": "Password"}, validators=[Length(min=4, max=20)])
    submit = SubmitField("Register")


# Login form
class LoginForm(FlaskForm):
    username = StringField(render_kw={"placeholder": "Username"})
    password = PasswordField(render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")


@app.route('/')
@login_required
def home():
    userid = current_user.get_id()
    return render_template("home.html", user_id=userid)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("home"))

    return render_template("login.html", form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        create_user = User(username=form.username.data, password=hash_password)
        db.session.add(create_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("registration.html", form=form)


if __name__ == "__main__":
    app.run(debug=True)
