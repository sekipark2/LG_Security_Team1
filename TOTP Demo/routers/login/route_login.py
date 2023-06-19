from typing import List

import routers.signup.forms
from core.hashing import Hasher
from core.otp import OTP
from database.models.users import User
from database.repository.users import get_user_by_email, create_session_key
from database.session import get_db
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from routers.login.forms import LoginForm

from pydantic import BaseModel

import time

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)

rest_session = {}
web_session = {}
contact_list = {}

class Contact:
    email: str
    hash_id: str
    ip_address: str
    rsa_public_key: str
    refresh_time: int
    first_name: str
    last_name: str
    is_server: bool

    def to_map(self):
        return {
            'email': self.email,
            'hash_id': self.hash_id,
            'ip_address': self.ip_address,
            'rsa_public_key': self.rsa_public_key,
            'refresh_time': self.refresh_time
        }

    def __hash__(self):
        return hash(self.hash_id)

    def expired(self):
        duration = round(time.time() * 1000) - self.refresh_time
        if duration > 1 * 60 * 60 * 1000:
            return True


@router.get("/login/")
def login(request: Request):
    return templates.TemplateResponse("login/login.html", {"request": request})


@router.post("/login/")
async def login(request: Request, db: Session = Depends(get_db)):
    form = LoginForm(request)
    await form.load_data()
    if await form.is_valid():
        try:
            user: User = get_user_by_email(form.email, db=db)
            print(user)
            if user:
                print('fail_counter', user.fail_counter)
                if user.fail_counter >= 3:
                    form.__dict__.get("errors").append("You entered the incorrect password more than three times")
                    return templates.TemplateResponse("login/login.html", form.__dict__)

                check_password = Hasher.verify_password(form.password, user.hashed_password)
                check_otp = OTP.verify_otp(user.secret, form.token)
                if not check_password:
                    user.fail_counter += 1
                    db.commit()
                if not check_password or not check_otp:
                    form.__dict__.get("errors").append("Incorrect Credentails")
                    return templates.TemplateResponse("login/login.html", form.__dict__)

            response = templates.TemplateResponse("home/index.html", {"request": request,
                                                                      "email": user.email,
                                                                      'first_name': user.first_name,
                                                                      'last_name': user.last_name,
                                                                      'address': user.address})
            session_key = create_session_key()
            web_session[session_key] = user.hash_id
            if user.fail_counter > 0:
                user.fail_counter = 0
                db.commit()
            response.set_cookie(key='login_session', value=session_key)
            return response
        except HTTPException:
            form.__dict__.update(msg="")
            form.__dict__.get("errors").append("Incorrect Email or Password")
            return templates.TemplateResponse("login/login.html", form.__dict__)
    return templates.TemplateResponse("login/login.html", form.__dict__)


class AppLoginData(BaseModel):
    email: str
    password: str
    token: str
    ip_address: str
    rsa_public_key: str
    errors: List = []

    async def is_valid(self):
        if not self.email or not (self.email.__contains__("@")):
            self.errors.append("Email is required")
        if not self.password or len(self.password) < routers.signup.forms.PASSWORD_LENGTH:
            self.errors.append("A valid password is required")
        if len(self.token) != 6:
            self.errors.append("Enter valid token")
        if not self.errors:
            return True
        return False


@router.post('/login_from_app')
async def login_from_app(app_login_data: AppLoginData, db: Session = Depends(get_db)):
    if not await app_login_data.is_valid():
        return {
            'errorCode': -1,
            'msg': ','.join(app_login_data.errors)
        }

    user: User = get_user_by_email(app_login_data.email, db=db)
    if user:
        print(user)
        if user.fail_counter >= 3:
            return {
                'errorCode': -1,
                'msg': 'You entered the incorrect password more than three times'
            }
        check_password = Hasher.verify_password(app_login_data.password, user.hashed_password)
        check_otp = OTP.verify_otp(user.secret, app_login_data.token)

        if not check_password:
            user.fail_counter += 1
            db.commit()
        if not check_otp or not check_password:
            return {
                'errorCode': -1,
                'msg': 'Incorrect Credentials'
            }
        time_diff = round(time.time() * 1000) - user.updated
        MONTH = 30 * 24 * 60 * 60 * 1000
        print(time_diff)
        if time_diff > MONTH:
            return {
                'errorCode': -1,
                'msg': 'Password is expired (> 30 days)'
            }
    else:
        app_login_data.__dict__.get("errors").append("Incorrect Credentials")
        return {
            'errorCode': -1,
            'msg': ','.join(app_login_data.errors)
        }

    if user.fail_counter > 0:
        user.fail_counter = 0
        db.commit()
    session_id = create_session_key()
    rest_session[user.hash_id] = session_id

    contact = Contact()
    contact.email = app_login_data.email
    contact.hash_id = user.hash_id
    contact.ip_address = app_login_data.ip_address
    contact.rsa_public_key = app_login_data.rsa_public_key
    # contact.refresh_time = round(time.time() * 1000)
    contact.first_name = user.first_name
    contact.last_name = user.last_name
    contact.is_server = False

    contact_list[contact.hash_id] = contact

    return {
        'errorCode': 0,
        'msg': 'Success',
        'session_id': session_id,
        'hash_id': user.hash_id
    }


def make_ret(code, msg):
    return {
        'errorCode': code,
        'msg': msg
    }


def check_session(hash_id, session_id):
    if hash_id not in rest_session.keys():
        return False, make_ret(-1, 'not logged in')

    if rest_session[hash_id] != session_id:
        return False, make_ret(-1, 'invalid connection')

    return True, {}


@router.get('/contacts')
async def get_contacts(hash_id, session_id):
    check_valid, err = check_session(hash_id, session_id)
    if not check_valid:
        return err

    return make_ret(0, [contact_list[i] for i in contact_list.keys()])


# class AppSessionData(BaseModel):
#     hash_id: str
#     session: str
#
#     async def is_valid(self):
#         if not self.hash_id:
#             self.errors.append("hash id is required")
#         if not self.session:
#             self.errors.append("A valid session is required")
#         if not self.errors:
#             return True
#         return False


class AppSessionData(BaseModel):
    session: str
    hash_id: str

    async def is_valid(self):
        if not self.hash_id:
            self.errors.append("hash id is required")
        if not self.session:
            self.errors.append("A valid session is required")
        if not self.errors:
            return True
        return False


class TurnOnServerData(AppSessionData):
    is_server: bool


class PeerData(AppSessionData):
    peer_hash_id: str



@router.post('/contacts')
async def get_contacts(app_session: AppSessionData):
    check_valid, err = check_session(app_session.hash_id, app_session.session)
    if not check_valid:
        return err

    return make_ret(0, [contact_list[i] for i in contact_list.keys()])


@router.post('/set_server')
async def turn_on_server(app_session: TurnOnServerData):
    check_valid, err = check_session(app_session.hash_id, app_session.session)
    if not check_valid:
        return err

    contact_list[app_session.hash_id].is_server = app_session.is_server
    return make_ret(0, 'ok')


@router.post('/check_peer')
async def check_peer(peer_data: PeerData):
    check_valid, err = check_session(peer_data.hash_id, peer_data.session)
    if not check_valid:
        return err
    if peer_data.peer_hash_id not in rest_session.keys():
        return make_ret(-1, 'not valid peer hash_id')
    return make_ret(0, contact_list[peer_data.peer_hash_id])
