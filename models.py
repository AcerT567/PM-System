from datetime import datetime
from flask_login import UserMixin
from sqlalchemy import (Column, Integer, String, DateTime, Text, ForeignKey)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(30), nullable=False)  # 'doctor', 'nurse', 'admin'
    created_at = Column(DateTime, default=datetime.utcnow)

class Patient(Base):
    __tablename__ = 'patients'
    id = Column(Integer, primary_key=True)
    first_name = Column(String(120), nullable=False)
    last_name = Column(String(120), nullable=False)
    dob = Column(String(30))
    gender = Column(String(20))
    phone = Column(String(40))
    email = Column(String(120))
    address = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    notes = relationship('Note', back_populates='patient', cascade='all, delete-orphan')

class Note(Base):
    __tablename__ = 'notes'
    id = Column(Integer, primary_key=True)
    patient_id = Column(Integer, ForeignKey('patients.id'))
    author_id = Column(Integer, ForeignKey('users.id'))
    title = Column(String(200))
    body = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    patient = relationship('Patient', back_populates='notes')
