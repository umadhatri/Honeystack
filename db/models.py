import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON, LargeBinary, Date, Boolean
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Event(Base):
    __tablename__ = 'events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    sensor_type = Column(String(10), nullable=False, index=True)  # 'SSH' or 'HTTP'
    source_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    processed = Column(Boolean, default=False, nullable=False, index=True)
    
    # SSH specific fields
    ssh_username = Column(String(255), nullable=True)
    ssh_password = Column(String(255), nullable=True)
    ssh_client_version = Column(String(255), nullable=True)
    ssh_commands = Column(JSON, nullable=True)  # List of strings (commands typed)
    
    # HTTP specific fields
    http_method = Column(String(10), nullable=True)
    http_path = Column(Text, nullable=True)
    http_query = Column(Text, nullable=True)
    http_headers = Column(JSON, nullable=True)
    http_body = Column(Text, nullable=True)
    http_user_agent = Column(Text, nullable=True)
    attack_type = Column(String(100), nullable=True)  # SQLi, XSS, Path Traversal, scan, etc.
    
    campaign_id = Column(Integer, ForeignKey('campaigns.id', ondelete='SET NULL'), nullable=True, index=True)
    
    # Relationships
    campaign = relationship("Campaign", back_populates="events")
    mitre_tags = relationship("MitreTag", back_populates="event", cascade="all, delete-orphan")

class IPProfile(Base):
    __tablename__ = 'ip_profiles'

    ip = Column(String(45), primary_key=True)
    abuse_score = Column(Integer, default=0)
    report_count = Column(Integer, default=0)
    country = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True)
    city = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    asn = Column(String(50), nullable=True)
    org = Column(String(255), nullable=True)
    last_enriched = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Credential(Base):
    __tablename__ = 'credentials'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    classification = Column(String(100), nullable=True)  # 'rockyou_top_1000', 'seclists_common', 'custom', etc.
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    attempt_count = Column(Integer, default=1)

class Campaign(Base):
    __tablename__ = 'campaigns'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    shared_credentials = Column(JSON, nullable=True)  # List of dicts/strings
    shared_user_agent = Column(Text, nullable=True)
    shared_commands = Column(JSON, nullable=True)  # List of commands
    start_time = Column(DateTime, default=datetime.datetime.utcnow)
    last_active = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    ip_count = Column(Integer, default=1)

    events = relationship("Event", back_populates="campaign")

class MitreTag(Base):
    __tablename__ = 'mitre_tags'

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey('events.id', ondelete='CASCADE'), nullable=False, index=True)
    technique_id = Column(String(50), nullable=False, index=True)  # e.g., T1110.001
    technique_name = Column(String(255), nullable=False)

    event = relationship("Event", back_populates="mitre_tags")

class Report(Base):
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    total_events = Column(Integer, default=0)
    unique_ips = Column(Integer, default=0)
    top_credentials = Column(JSON, nullable=True)
    top_countries = Column(JSON, nullable=True)
    detected_campaigns = Column(JSON, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)
    executive_summary = Column(Text, nullable=True)
    pdf_content = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
