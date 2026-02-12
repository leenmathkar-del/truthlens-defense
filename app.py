from flask import Flask, render_template, redirect, url_for, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import requests
import os
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# =======================
# Database Models
# =======================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(50), default="Analyst")

class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =======================
# AI API Simulation
# =======================

def analyze_image():
    # هنا تحطين API حقيقي
    # حالياً نحاكي نتيجة
    import random
    results = ["SAFE", "AI Manipulated", "Deepfake Suspected"]
    return random.choice(results)

# =======================
# Routes
# =======================

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        hashed_password = generate_password_hash(request.form["password"])
        new_user = User(
            username=request.form["username"],
            password=hashed_password,
            role="Analyst"
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    logs = ThreatLog.query.all()
    threat_count = ThreatLog.query.count()
    return render_template("dashboard.html",
                           name=current_user.username,
                           role=current_user.role,
                           logs=logs,
                           threat_count=threat_count)

@app.route("/scan")
@login_required
def scan():
    result = analyze_image()
    new_log = ThreatLog(result=result)
    db.session.add(new_log)
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/generate-report")
@login_required
def generate_report():
    file_path = "threat_report.pdf"
    doc = SimpleDocTemplate(file_path)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph("TruthLens Defense Report", styles["Title"]))
    elements.append(Spacer(1, 0.3 * inch))

    logs = ThreatLog.query.all()
    for log in logs:
        elements.append(Paragraph(f"{log.timestamp} - {log.result}", styles["Normal"]))
        elements.append(Spacer(1, 0.2 * inch))

    doc.build(elements)

    return send_file(file_path, as_attachment=True)

@app.route("/admin")
@login_required
def admin():
    if current_user.role != "Admin":
        return "Access Denied"
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
