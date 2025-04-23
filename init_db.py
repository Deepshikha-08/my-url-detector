from sqlalchemy import inspect
from models import db, User, URLCheck  
from app import app

def upgrade_database():
    with app.app_context():
        inspector = inspect(db.engine)
        existing_columns = {col["name"] for col in inspector.get_columns("url_check")}
        new_columns = {
            "category": "'suspicious'",
            "ssl_status": "'Unknown'",
            "last_scan": "'Not Scanned'",
            "whois_info": "''"
        }

        for column, default_value in new_columns.items():
            if column not in existing_columns:
                db.engine.execute(f"ALTER TABLE url_check ADD COLUMN {column} TEXT DEFAULT {default_value}")

        db.session.commit()
        print(" Database updated successfully!")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  
        upgrade_database()
        print("All tasks completed successfully!")
