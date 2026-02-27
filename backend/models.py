from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)  # In production, use hashing like passlib/bcrypt

class LogEntry(Base):
    __tablename__ = "log_entries"
    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(String, index=True)
    timestamp = Column(DateTime, index=True)
    source_ip = Column(String, index=True)
    http_method = Column(String)
    endpoint = Column(String)
    status_code = Column(Integer)
    response_size = Column(Integer)
    user_agent = Column(String)
    is_anomaly = Column(Boolean, default=False)
    anomaly_reason = Column(String, nullable=True) 
    confidence_score = Column(Float, nullable=True)
    category = Column(String, default="Normal")