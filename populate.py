from app import app, db, User
from werkzeug.security import generate_password_hash

def populate_users():
    with app.app_context():
        # List of users to add
        users = [
            {'username': 'admin', 'email': 'aquadetect001@gmail.com', 'password': 'admin123'},
            {'username': 'user1', 'email': 'dion.alimoren@gmail.com', 'password': 'user123'},
            {'username': 'user2', 'email': 'aquadetect1@gmail.com', 'password': 'pass456'},
        ]

        for user in users:
            # Check if the user already exists
            existing_user = User.query.filter_by(email=user['email']).first()
            if existing_user:
                print(f"User with email {user['email']} already exists.")
                continue

            # Hash the password
            hashed_password = generate_password_hash(user['password'], method='pbkdf2:sha256')

            # Create a new user and save to the database
            new_user = User(username=user['username'], email=user['email'], password=hashed_password)
            db.session.add(new_user)

        # Commit the changes to the database
        db.session.commit()

if __name__ == "__main__":
    populate_users()
