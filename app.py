from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# ===============================
# DATABASE MODELS
# ===============================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="Analyst")

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default="Open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# ===============================
# LOGIN MANAGER
# ===============================

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ===============================
# ROUTES
# ===============================

@app.route("/")
def home():
    return render_template("index.html")

# -------- Register --------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        new_user = User(username=username, password=password, role="Analyst")
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully!", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# -------- Login --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger")

    return render_template("login.html")

# -------- Logout --------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

# -------- Dashboard --------
@app.route("/dashboard")
@login_required
def dashboard():
    total_incidents = Incident.query.count()
    open_incidents = Incident.query.filter_by(status="Open").count()
    closed_incidents = Incident.query.filter_by(status="Closed").count()

    return render_template(
        "dashboard.html",
        total=total_incidents,
        open=open_incidents,
        closed=closed_incidents
    )

# ===============================
# INCIDENT RESPONSE SYSTEM
# ===============================

@app.route("/incidents")
@login_required
def incidents():
    if current_user.role == "Admin":
        all_incidents = Incident.query.all()
    else:
        all_incidents = Incident.query.filter_by(created_by=current_user.id).all()

    return render_template("incidents.html", incidents=all_incidents)

@app.route("/create_incident", methods=["POST"])
@login_required
def create_incident():
    title = request.form["title"]
    description = request.form["description"]
    severity = request.form["severity"]

    new_incident = Incident(
        title=title,
        description=description,
        severity=severity,
        created_by=current_user.id
    )

    db.session.add(new_incident)
    db.session.commit()

    return redirect(url_for("incidents"))

@app.route("/update_status/<int:id>")
@login_required
def update_status(id):
    incident = Incident.query.get_or_404(id)

    if current_user.role == "Admin":
        if incident.status == "Open":
            incident.status = "In Progress"
        elif incident.status == "In Progress":
            incident.status = "Closed"

        db.session.commit()

    return redirect(url_for("incidents"))

# ===============================
# DATABASE INIT
# ===============================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
