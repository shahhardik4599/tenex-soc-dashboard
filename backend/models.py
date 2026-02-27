from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime
from database import Base

class LogEntry(Base):
    __tablename__ = "log_entries"

    id = Column(Integer, primary_key=True, index=True)
    batch_id = Column(String, index=True) # ADD THIS LINE!
    timestamp = Column(DateTime, index=True)
    source_ip = Column(String, index=True)
    http_method = Column(String)
    endpoint = Column(String)
    status_code = Column(Integer)
    response_size = Column(Integer)
    user_agent = Column(String)
    
    # AI & Detection Fields
    is_anomaly = Column(Boolean, default=False)
    anomaly_reason = Column(String, nullable=True) 
    confidence_score = Column(Float, nullable=True)