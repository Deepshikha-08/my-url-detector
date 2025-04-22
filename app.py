import os
import re
import requests
import time
import traceback
from datetime import datetime, timedelta
from collections import Counter
import pytz
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from dotenv import load_dotenv
from flask_migrate import Migrate
import sqlite3
from models import URLCheck  
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
import tldextract
import json

load_dotenv()

LOCAL_TIMEZONE = pytz.timezone("Asia/Kolkata")

# Initialize Flask app
app = Flask(__name__)
CORS(app)  
app.secret_key = os.getenv("SECRET_KEY", "super_secret_key")

basedir = os.path.abspath(os.path.dirname(__file__))
instance_dir = os.path.join(basedir, 'instance')
os.makedirs(instance_dir, exist_ok=True)

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(instance_dir, 'urls.db')}"
app.config['SQLALCHEMY_BINDS'] = {
    'extension_db': f"sqlite:///{os.path.join(instance_dir, 'extension_check.db')}"
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
target_metadata = db.metadata

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))

    def __repr__(self):
        return f'<Contact {self.name}>'
    
@app.route('/contact', methods=['POST'])
def submit_contact():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']

    if not name or not email or not message:
        flash("All fields are required.", "error")
        return redirect(url_for('contact'))

    new_contact = Contact(name=name, email=email, message=message)
    db.session.add(new_contact)
    db.session.commit()

    flash("Your message has been sent successfully!", "success")
    return redirect(url_for('contact'))

class URLCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2083), unique=True, nullable=False)
    result = db.Column(db.String(20), nullable=False) 
    ssl_status = db.Column(db.String(100), nullable=True) 
    whois_link = db.Column(db.String(255), nullable=True)
    whois_data = db.Column(db.Text, nullable=True)
    last_scan = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))
    date_time = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))


class ExtensionURLCheck(db.Model):
    __tablename__ = "extension_url_check"
    __bind_key__ = 'extension_db'  
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False)  
    ssl_status = db.Column(db.String(10), nullable=True)  
    whois_link = db.Column(db.String(255), nullable=True)
    whois_data = db.Column(db.Text, nullable=True)
    scan_date = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))
    last_scan = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))


# Route to receive URLs from the extension
@app.route('/store_extension_url', methods=['POST']) 
def store_extension_url():
    try:
        data = request.get_json()
        url = data.get("url", "").strip()

        if not url:
            return jsonify({"message": "Invalid URL!", "result": "error"}), 400
        result = classify_url(url) or "safe"  

        with app.app_context():
            existing_entry = ExtensionURLCheck.query.filter_by(url=url).first()
            if existing_entry:
                existing_entry.result = result
                db.session.commit()
                print(f" Updated URL: {url}, Result: {existing_entry.result}")
                return jsonify({"message": "URL scan updated!", "result": existing_entry.result})
            # Get additional info
            ssl_status = check_ssl(url)
            whois_link = get_whois_link(url)

            domain_info = tldextract.extract(url)
            domain = f"{domain_info.domain}.{domain_info.suffix}"
            whois_record = get_whois_data(domain)

            whois_data = json.dumps(whois_record) if isinstance(whois_record, dict) else str(whois_record)

            # Create new DB entry with all fields
            new_entry = ExtensionURLCheck(
                url=url,
                result=result,
                ssl_status=ssl_status,
                whois_link=whois_link,
                whois_data=whois_data
            )

            db.session.add(new_entry)
            db.session.commit()
            print(f"Stored new URL: {url}, Result: {new_entry.result}")
            return jsonify({"message": "URL stored successfully!", "result": new_entry.result})

    except Exception as e:
        print(f"Error storing URL: {e}")
        return jsonify({"message": "Error storing URL", "result": "error"}), 500
    
# Route to retrieve all stored URLs
@app.route("/get_extension_urls", methods=["GET"])
def get_extension_urls():
    urls = ExtensionURLCheck.query.all()
    
    if not urls:
        print("No URLs found in the database!")
        return jsonify({"message": "No URLs found!", "result": "error"}), 404

    # Prepare the list of URLs with necessary fields
    urls_list = [{"id": url.id,
                  "url": url.url,
                  "result": url.result,
                  "ssl_status": url.ssl_status,
                  "whois_link": url.whois_link,
                  "whois_data": url.whois_data,
                  "scan_date": url.scan_date,
                  "last_scan": url.last_scan,
    } for url in urls]
    return jsonify(urls_list)

# Google Safe Browsing Check
def check_google_safe_browsing(url):
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    if not GOOGLE_API_KEY:
        return "safe"

    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "suspicious-url-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(safe_browsing_url, json=payload, params={"key": GOOGLE_API_KEY}, timeout=5)
        response.raise_for_status()
        return "malicious" if "matches" in response.json() else "safe"
    except requests.exceptions.Timeout:
        return "unknown"
    except requests.exceptions.RequestException:
        return "unknown"

# WHOIS API Function
def get_whois_data(domain):
    API_KEY = os.getenv("WHOIS_API_KEY")  
    if not API_KEY:
        return {"error": "WHOIS API key is missing!"}

    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={API_KEY}&domainName={domain}&outputFormat=json"
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        whois_data = response.json()

        if "WhoisRecord" not in whois_data:
            return {"error": "Invalid WHOIS response"}
        
        return whois_data["WhoisRecord"]  
    except requests.exceptions.Timeout:
        return {"error": "WHOIS request timed out"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    
@app.route("/whois", methods=["POST"])
def get_whois_info():
    data = request.json
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    whois_data = get_whois_data(domain)  

    if "error" in whois_data:
        return jsonify({"error": whois_data["error"]}), 500

    return jsonify(whois_data)

# Check SSL Status
def check_ssl(url):
    if not url or not isinstance(url, str):
        return "Unknown"
    return "Valid" if url.startswith("https://") else "Invalid"


# Get WHOIS Link
def get_whois_link(url):
    try:
        return f"https://who.is/whois/{urlparse(url).netloc}"
    except Exception:
        return None


# URL Format Validation
def is_valid_url(url):
    url_regex = re.compile(r"^(https?://)?([\w.-]+\.[a-zA-Z]{2,10})(/[^\s]*)?$", re.IGNORECASE)
    return bool(re.match(url_regex, url))

# URL Classification
def classify_url(url):
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    subdomains = domain_info.subdomain.split('.') if domain_info.subdomain else []

    # Call Safe Browsing API
    google_result = check_google_safe_browsing(url) or "safe"  

    if google_result == "malicious":
        print(f"URL classified as malicious by Google Safe Browsing: {url}")
        return "malicious"

    # List of suspicious TLDs
    suspicious_tlds = {".xyz", ".top", ".info", ".biz", ".work", ".club", ".online", ".site", ".shop"}
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        print(f"URL classified as suspicious due to TLD: {url}")
        return "suspicious"

    # Check for too many subdomains
    if len(subdomains) > 2:
        print(f"URL classified as suspicious due to subdomain count: {url}")
        return "suspicious"

    # Suspicious patterns in URL
    suspicious_patterns = [
        r"[a-zA-Z0-9]+-[a-zA-Z0-9]+",  # Hyphenated words
        r"\b\d{1,3}(\.\d{1,3}){3}\b",  # IP address in URL
        r"\b(free|login|bank|verify|secure|click|update|confirm|password|account|urgent|payment|support|service|win|prize)\b",
    ]
    
    try:
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns):
            print(f"URL classified as suspicious due to pattern match: {url}")
            return "suspicious"
    except re.error as e:
        print(f" Regex error: {e}")

    url_shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
    if domain in url_shorteners:
        print(f"URL classified as suspicious due to URL shortener: {url}")
        return "suspicious"

    # If no suspicious signals, return safe
    print(f" URL classified as safe: {url}")
    return "safe"

@app.route('/analytics', methods=['GET'])
def analytics():
    return render_template("analytics.html")  #  Render an HTML page instead of JSON

@app.route('/analytics/data', methods=['GET'])
def analytics_data():
    try:
        total_checks = URLCheck.query.count()
        results = [entry.result for entry in URLCheck.query.all()]
        result_counts = Counter(results)
        week_ago = datetime.now() - timedelta(days=7)
        last_week_checks = URLCheck.query.filter(URLCheck.date_time.isnot(None), URLCheck.date_time >= week_ago).count()

        return jsonify({
            "total_checks": total_checks,
            "safe_count": result_counts.get("safe", 0),
            "suspicious_count": result_counts.get("suspicious", 0),
            "malicious_count": result_counts.get("malicious", 0),
            "last_week_checks": last_week_checks
        })
    except Exception as e:
        print("Error in analytics_data():", e)
        return jsonify({"error": str(e)}), 500

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    query = data.get('query', '').strip()

    print(f"Received search query: {query}")  # Debugging log
    
    if not query:
        return jsonify({'results': []})
    
    search_results = URLCheck.query.filter(URLCheck.url.ilike(f"%{query}%")).all()

    results = [{
        'url': entry.url,
        'result': entry.result,
        'date': entry.date_time.strftime('%Y-%m-%d %H:%M:%S')
    } for entry in search_results]

    return jsonify({'results': results})

# URL Scan Route
@app.route('/scan', methods=['POST'])
def scan_url():
    url = request.form.get('url', '').strip()

    if not is_valid_url(url):
        flash("Invalid URL format!", "error")
        return redirect(url_for('home'))

    with app.app_context():
        existing_entry = URLCheck.query.filter_by(url=url).first()
        if existing_entry:
            flash("This URL has already been scanned. Check results!", "info")
            return redirect(url_for('result'))

        result = classify_url(url)
        ssl_status = check_ssl(url)
        whois_link = get_whois_link(url)
        whois_data = get_whois_data(urlparse(url).netloc)  # Fetch WHOIS data correctly

        new_entry = URLCheck(url=url, result=result, ssl_status=ssl_status, whois_link=whois_link, whois_data=str(whois_data))
        db.session.add(new_entry)
        db.session.commit()

    flash("URL scanned successfully!", "success")
    return redirect(url_for('result'))

# Routes
@app.route('/')
def home():
    whois_data = {} 
    return render_template('index.html',whois_data=whois_data)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/result', methods=['GET'])
def result():
    with app.app_context():
        try:
            urls = db.session.query(URLCheck).order_by(URLCheck.date_time.desc()).all()
            return render_template('result.html', scans=urls)
        except Exception as e:
            print(" Error fetching results:", str(e))
            return f"Error: {str(e)}", 500
        
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        message = request.form['message'].strip()

        # Debug prints
        print(f"Name: {repr(name)}")
        print(f"Email: {repr(email)}")
        print(f"Message: {repr(message)}")

        if not re.fullmatch(r'[A-Za-z ]{3,}', name):
            flash('Name must be at least 3 characters and contain only letters and spaces.', 'error')
            return redirect(url_for('contact'))

        # Email validation
        if not re.fullmatch(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('contact'))
        
        if len(message) < 10:
            flash('Message must be at least 10 characters long.', 'error')
            return redirect(url_for('contact'))

        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

def fix_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  
    return url

# API for Chrome Extension
@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        if not request.is_json:
            return jsonify({"message": "Invalid request format! Use JSON.", "result": "error"}), 415

        data = request.get_json()
        url = data.get("url", "").strip()
        source = data.get("source", "web")

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        if not domain:
            return jsonify({"message": "Invalid URL format!", "result": "error"}), 400
        ssl_status = "unknown"

        with app.app_context():
            existing_entry = URLCheck.query.filter_by(url=url).first()
            if existing_entry:
                result = existing_entry.result
                whois_data = existing_entry.whois_data or get_whois_data(domain)
                ssl_status = existing_entry.ssl_status
                existing_entry.last_scan = datetime.now(LOCAL_TIMEZONE)
                db.session.commit()
            else:
                whois_data = get_whois_data(domain)
                result = classify_url(url) 
                ssl_status = check_ssl(url)

                if source != "extension":
                    new_entry = URLCheck(
                        url=url,
                        result=result,
                        ssl_status=ssl_status,
                        whois_link=f"https://who.is/whois/{domain}",
                        whois_data=str(whois_data),
                        last_scan=datetime.now(LOCAL_TIMEZONE)
                    )
                    db.session.add(new_entry)
                    db.session.commit()
        return jsonify({
            "message": "URL scanned successfully!",
            "result": result,
            "ssl_status": ssl_status,
            "whois_link": f"https://who.is/whois/{domain}",
            "whois_data": whois_data
        })

    except Exception as e:
        print(f"Server Error: {e}")
        return jsonify({"message": "Error processing request", "result": "error", "error": str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)