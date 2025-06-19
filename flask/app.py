# Xolar Software - Premium Payment System with Login, Cookies, DB, MTN & Airtel

from flask import Flask, request, render_template, redirect, session, make_response
import sqlite3
import bcrypt
import uuid
import requests

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production
DATABASE = 'xolar.db'

# --- Helper Functions ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_premium BOOLEAN DEFAULT FALSE
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount DECIMAL(10, 2),
            method TEXT,
            status TEXT,
            reference TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )''')


# --- Routes ---
@app.route('/')
def home():
    return '''
    <h2>Welcome to Xolar Software</h2>
    <p><a href="/register">Register</a> | <a href="/login">Login</a></p>
    '''

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt())

        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
                return redirect('/login')
        except sqlite3.IntegrityError:
            return "Email already exists."

    return '''
    <h2>Register</h2>
    <form method="post">
        Email: <input type="email" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Register">
    </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode()

        with sqlite3.connect(DATABASE) as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and bcrypt.checkpw(password, user[2]):
                session['user_id'] = user[0]
                resp = make_response(redirect('/dashboard'))
                resp.set_cookie('session_token', str(uuid.uuid4()), max_age=3600)
                return resp
        return "Invalid credentials."

    return '''
    <h2>Login</h2>
    <form method="post">
        Email: <input type="email" name="email" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    with sqlite3.connect(DATABASE) as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        premium_status = "Premium" if user[3] else "Free"
        return f'''
        <h2>Dashboard</h2>
        <p>Welcome, {user[1]}</p>
        <p>Status: {premium_status}</p>
        <form method="post" action="/pay">
            <label>Select Payment Method:</label><br>
            <input type="radio" name="method" value="mtn" required> MTN<br>
            <input type="radio" name="method" value="airtel"> Airtel<br>
            <input type="submit" value="Pay UGX 10,000">
        </form>
        <p><a href="/logout">Logout</a></p>
        '''

@app.route('/pay', methods=['POST'])
def pay():
    if 'user_id' not in session:
        return redirect('/login')

    method = request.form['method']  # 'mtn' or 'airtel'
    amount = 10000  # UGX fixed price
    reference = str(uuid.uuid4())

    # Simulate or integrate with Flutterwave (replace keys and URL)
    api_url = "https://api.flutterwave.com/v3/payments"
    headers = {
        "Authorization": "Bearer FLW_SECRET_KEY",
        "Content-Type": "application/json"
    }
    with sqlite3.connect(DATABASE) as conn:
        user = conn.execute("SELECT email FROM users WHERE id=?", (session['user_id'],)).fetchone()
    data = {
        "tx_ref": reference,
        "amount": amount,
        "currency": "UGX",
        "payment_options": method,
        "redirect_url": "http://localhost:5000/payment_callback",
        "customer": {
            "email": user[0]
        },
        "customizations": {
            "title": "Xolar Premium Access",
            "description": "Upgrade to premium"
        }
    }

    response = requests.post(api_url, json=data, headers=headers)
    if response.status_code == 200:
        result = response.json()
        payment_link = result['data']['link']
        return redirect(payment_link)
    else:
        return "Payment initialization failed"

@app.route('/payment_callback')
def payment_callback():
    # Here you should verify transaction with Flutterwave API and mark user as premium
    tx_ref = request.args.get('tx_ref')
    status = request.args.get('status')

    if status == "successful":
        with sqlite3.connect(DATABASE) as conn:
            conn.execute("UPDATE users SET is_premium=1 WHERE id=?", (session['user_id'],))
            conn.execute("INSERT INTO payments (user_id, amount, method, status, reference) VALUES (?, ?, ?, ?, ?)",
                         (session['user_id'], 10000, 'flutterwave', 'successful', tx_ref))
        return redirect('/dashboard')
    else:
        return "Payment was not successful."

@app.route('/logout')
def logout():
    session.clear()
    resp = make_response(redirect('/'))
    resp.set_cookie('session_token', '', max_age=0)
    return resp


# --- Initialize DB ---
if __name__ == '__main__':
    init_db()
    app.run(debug=True)

