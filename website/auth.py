from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

auth = Blueprint("auth", __name__)


@auth.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("وارد شدید", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('پسورد نادرست است', category='error')
        else:
            flash('ایمیل وجود ندارد', category='error')

    return render_template("login.html", user=current_user)


@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()

        if email_exists:
            flash('ایمیل در حال حاضر  وجود دارد', category='error')
        elif username_exists:
            flash('نام کاربری در حال حاضر وجود دارد', category='error')
        elif password1 != password2:
            flash('پسورد مطابقت ندارد', category='error')
        elif len(username) < 2:
            flash('نام کاربری کوتاه است', category='error')
        elif len(password1) < 6:
            flash('پسورد کوتاه است', category='error')
        elif len(email) < 4:
            flash("ایمیل نامعتبر است", category='error')
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('نام کاربری ایجاد شد')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("views.home"))
