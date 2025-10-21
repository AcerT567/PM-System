# Initializes the SQLite database and creates sample users.
from werkzeug.security import generate_password_hash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'pms.db')
engine = create_engine(f'sqlite:///{DB_PATH}', echo=False, future=True)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine, future=True)
session = Session()

def create_user(username, password, role):
    existing = session.query(User).filter_by(username=username).first()
    if existing:
        print(f'User {username} exists, skipping.')
        return
    u = User(username=username, password_hash=generate_password_hash(password), role=role)
    session.add(u)
    session.commit()
    print(f'Created user: {username} ({role})')

if __name__ == '__main__':
    create_user('doctor1', 'Password123', 'doctor')
    create_user('nurse1', 'Password123', 'nurse')
    create_user('admin', 'AdminPass123', 'admin')
    print('Database initialized at', DB_PATH)
