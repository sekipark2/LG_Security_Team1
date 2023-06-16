from core.hashing import Hasher
from database.models.users import User
from schemas.users import UserCreate
from sqlalchemy.orm import Session
import time

def create_new_user(user: UserCreate, db: Session):
    user = User(
        email=user.email,
        hashed_password=Hasher.get_password_hash(user.password),
        secret=user.secret,
        verified=user.verified,
        fail_counter=user.fail_counter,
        updated=round(time.time() * 1000),
        hash_id=Hasher.get_password_hash(user.email)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_email(email: str, db: Session):
    user = db.query(User).filter(User.email == email).first()
    return user