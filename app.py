from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from datetime import datetime
import requests
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
AI_API_KEY = os.getenv("AI_API_KEY")
AI_API_URL = "https://api.deepai.org/api/image-similarity"
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

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created!", "success")
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
    total = Incident.query.count()
    open_incidents = Incident.query.filter_by(status="Open").count()
    closed_incidents = Incident.query.filter_by(status="Closed").count()

    return render_template(
        "dashboard.html",
        total=total,
        open=open_incidents,
        closed=closed_incidents
    )

# ===============================
# INCIDENT SYSTEM
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
# EXPORT PDF
# ===============================

@app.route("/incident_pdf/<int:id>")
@login_required
def incident_pdf(id):
    incident = Incident.query.get_or_404(id)

    file_path = f"static/incident_{id}.pdf"
    doc = SimpleDocTemplate(file_path, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph("TruthLens Defense - Incident Report", styles["Heading1"]))
    elements.append(Spacer(1, 20))

    data = [
        ["Title", incident.title],
        ["Severity", incident.severity],
        ["Status", incident.status],
        ["Created At", str(incident.created_at)],
    ]

    table = Table(data, colWidths=[150, 300])
    table.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 1, colors.black),
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
    ]))

    elements.append(table)
    doc.build(elements)

    return send_file(file_path, as_attachment=True)

# ===============================
# ADMIN PANEL
# ===============================

@app.route("/admin")
@login_required
def admin_panel():
    if current_user.role != "Admin":
        return "Access Denied"

    users = User.query.all()
    incidents = Incident.query.all()

    return render_template("admin.html", users=users, incidents=incidents)
        # ===============================
# AI IMAGE ANALYSIS
# ===============================

@app.route("/analyze_image", methods=["POST"])
@login_required
def analyze_image():

    if "image" not in request.files:
        return {"error": "No image uploaded"}, 400

    image = request.files["image"]

    try:
        response = requests.post(
            AI_API_URL,
            files={"image": image},
            headers={"api-key": AI_API_KEY}
        )

        result = response.json()

        # مثال استخراج نتيجة
        confidence = result.get("output", {}).get("distance", 0.5)

        if confidence > 0.7:
            threat_level = "High"
        elif confidence > 0.4:
            threat_level = "Medium"
        else:
            threat_level = "Low"

        return {
            "status": "success",
            "confidence": confidence,
            "threat_level": threat_level
        }

    except Exception as e:
        return {"error": str(e)}, 500
# ===============================
# DATABASE INIT
# ===============================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
