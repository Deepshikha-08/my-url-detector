from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
from datetime import datetime

db = SQLAlchemy()

LOCAL_TIMEZONE = pytz.timezone("Asia/Kolkata")

class URLCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2083), unique=True, nullable=False)
    result = db.Column(db.String(20), nullable=False)  # Safe, Suspicious, Malicious
    ssl_status = db.Column(db.String(10), nullable=True)  # Valid, Invalid
    whois_link = db.Column(db.String(255), nullable=True)
    whois_data = db.Column(db.Text, nullable=True)
    last_scan = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))
    date_time = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(LOCAL_TIMEZONE))

    def __repr__(self):
        return f"<URLCheck {self.url}>"
