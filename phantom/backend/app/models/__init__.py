# app/models/__init__.py
# Re-export all model classes from the models.py file at the app level.
# This directory was created for future modular splitting; for now we proxy
# the existing app/models.py file which is in the parent 'app/' directory.
# NOTE: app/models.py is the actual file — it must NOT conflict with this package.
# Since Python resolves packages (directories) before modules (.py files),
# we define all models inline here to avoid the conflict.

import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String, nullable=True)
    google_id = Column(String, unique=True, nullable=True)
    github_id = Column(String, unique=True, nullable=True)
    role = Column(String, default="user")  # admin, user


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    target = Column(String, nullable=False)
    status = Column(String, default="running")  # running, completed, failed
    overall_risk = Column(String, default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    modules_run = Column(JSON, nullable=True)  # list of module names

    results = relationship("ScanResult", back_populates="session", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="session", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    module_name = Column(String, nullable=False)
    risk_level = Column(String, default="INFO")
    vulnerable = Column(Boolean, default=False)
    duration_seconds = Column(Float, default=0.0)
    result_data = Column(JSON, nullable=True)
    error_message = Column(String, nullable=True)

    session = relationship("ScanSession", back_populates="results")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="CASCADE"), nullable=False)
    module_name = Column(String, nullable=False)
    severity = Column(String, default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description = Column(String, nullable=False)
    acknowledged = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    session = relationship("ScanSession", back_populates="alerts")


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(Integer, ForeignKey("scan_sessions.id", ondelete="SET NULL"), nullable=True)
    filename = Column(String, nullable=False)
    storage_path = Column(String, unique=True, nullable=False)
    target = Column(String, nullable=False)
    overall_risk = Column(String, default="INFO")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
