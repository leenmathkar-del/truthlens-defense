import os
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt

# ==============================
# APP CONFIG
# ==============================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    "sqlite:///truthlens.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ==============================
# MODELS
# ==============================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="analyst")

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    threat_level = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ==============================
# JWT DECORATOR
# ==============================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")

        if not token:
            return jsonify({"error": "Token missing"}), 401

        try:
            data = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms=["HS256"]
            )
            current_user = User.query.get(data["user_id"])
        except:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# ==============================
# ROUTES
# ==============================

@app.route("/")
def home():
    return render_template("index.html")

# ------------------------------
# REGISTER
# ------------------------------

@app.route("/register", methods=["POST"])
def register():
    data = request.json

    hashed_password = bcrypt.generate_password_hash(
        data["password"]
    ).decode("utf-8")

    new_user = User(
        username=data["username"],
        password=hashed_password,
        role="analyst"
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"})

# ------------------------------
# LOGIN
# ------------------------------

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(username=data["username"]).first()

    if not user or not bcrypt.check_password_hash(
        user.password,
        data["password"]
    ):
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.utcnow() + timedelta(hours=8)
        },
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

    return jsonify({"token": token})

# ------------------------------
# CREATE REPORT
# ------------------------------

@app.route("/create_report", methods=["POST"])
@token_required
def create_report(current_user):
    data = request.json

    report = Report(
        title=data["title"],
        description=data["description"],
        threat_level=data["threat_level"]
    )

    db.session.add(report)
    db.session.commit()

    return jsonify({"message": "Report created"})

# ------------------------------
# GET REPORTS
# ------------------------------

@app.route("/reports", methods=["GET"])
@token_required
def get_reports(current_user):
    reports = Report.query.all()

    output = []
    for r in reports:
        output.append({
            "id": r.id,
            "title": r.title,
            "threat_level": r.threat_level,
            "created_at": r.created_at
        })

    return jsonify(output)

# ------------------------------
# ANALYZE IMAGE
# ------------------------------

@app.route("/analyze_image", methods=["POST"])
def analyze_image():
    file = request.files.get("image")

    if not file:
        return "No image uploaded", 400

    # حالياً تحليل وهمي
    return jsonify({
        "result": "AI Generated",
        "confidence": "87%"
    })

# ==============================
# DATABASE INIT (المكان الصحيح)
# ==============================

with app.app_context():
    db.create_all()
