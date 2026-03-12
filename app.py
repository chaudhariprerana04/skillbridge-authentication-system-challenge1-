from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = 'skillbridge_secret'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ---------------- Model ----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.LargeBinary)
    role = db.Column(db.String(20))

# ---------------- Pages ----------------

@app.route("/")
def home():
    return render_template("signup.html")

@app.route("/signup-page")
def signup_page():
    return render_template("signup.html")

@app.route("/login-page")
def login_page():
    return render_template("login.html")

@app.route("/dashboard-page")
def dashboard_page():
    return render_template("dashboard.html")

# ---------------- Signup API ----------------

@app.route("/signup", methods=["POST"])
def signup():

    data = request.json

    hashed_password = bcrypt.hashpw(
        data["password"].encode("utf-8"),
        bcrypt.gensalt()
    )

    user = User(
        name=data["name"],
        email=data["email"],
        password=hashed_password,
        role=data["role"]
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "Signup Successful"})

# ---------------- Login API ----------------

@app.route("/login", methods=["POST"])
def login():

    data = request.json

    user = User.query.filter_by(email=data["email"]).first()

    if user and bcrypt.checkpw(
        data["password"].encode("utf-8"),
        user.password
    ):

        token = create_access_token(identity=user.email)

        return jsonify({
            "message": "Login Successful",
            "token": token
        })

    return jsonify({"message": "Invalid Email or Password"})

# ---------------- Protected Route ----------------

@app.route("/dashboard")
@jwt_required()
def dashboard():

    current_user = get_jwt_identity()

    return jsonify({
        "message": f"Welcome {current_user}, this is a protected route"
    })

# ---------------- Run ----------------

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)