from core.hashing import Hasher
from database.models.users import User
from schemas.users import UserCreate
from sqlalchemy.orm import Session
import time
import base64
import os


def create_session_key():
    return base64.b32encode(os.urandom(10)).decode('utf-8')


def create_new_user(user: UserCreate, db: Session):
    user = User(
        email=user.email,
        hashed_password=Hasher.get_password_hash(user.password),
        secret=user.secret,
        verified=user.verified,
        fail_counter=user.fail_counter,
        updated=round(time.time() * 1000),
        hash_id=create_session_key(),
        first_name=user.first_name,
        last_name=user.last_name,
        address=user.address
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_email(email: str, db: Session):
    user = db.query(User).filter(User.email == email).first()
    return user


def get_user_by_hash_id(hash_id: str, db: Session):
    user = db.query(User).filter(User.hash_id == hash_id).first()
    return user