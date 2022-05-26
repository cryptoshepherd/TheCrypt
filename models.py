from sqlalchemy.sql import func
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime
)

from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Crypt(Base):
    __tablename__ = 'crypt'
    id = Column(Integer, primary_key=True)
    username = Column(String(20), nullable=False)
    password = Column(String(32), nullable=False)
    url = Column(String(50))
    date_created = Column(DateTime(timezone=True), default=func.now())
