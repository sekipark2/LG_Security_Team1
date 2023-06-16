from database.base_class import Base
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Boolean


class User(Base):
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    secret = Column(String, nullable=False)
    verified = Column(Boolean, nullable=False)
    fail_counter = Column(Integer, nullable=False)
    updated = Column(Integer, nullable=False)
    hash_id = Column(String, unique=True, nullable=False)
# Add first name, last name, ip address, public key, ...

