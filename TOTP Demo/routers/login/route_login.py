from typing import List

import routers.signup.forms
from core.hashing import Hasher
from core.otp import OTP
from database.models.users import User
from database.repository.users import get_user_by_email
from database.session import get_db
from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Request, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from routers.login.forms import LoginForm

from pydantic import BaseModel
import base64
import os
import json

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)

rest_session = {}
web_session = {}
contact_list = set()


def create_session_key():
    return base64.b32encode(os.urandom(10)).decode('utf-8')


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
            if user:
                print('fail_counter', user.fail_counter)
                if user.fail_counter >= 3:
                    form.__dict__.get("errors").append("You entered the incorrect password more than three times")
                    return templates.TemplateResponse("login/login.html", form.__dict__)

                check_password = Hasher.verify_password(form.password, user.hashed_password) \
                                 and OTP.verify_otp(user.secret, form.token)
                if not check_password:
                    user.fail_counter += 1
                    db.commit()

                    form.__dict__.get("errors").append("Incorrect Credentails")
                    return templates.TemplateResponse("login/login.html", form.__dict__)

            response = templates.TemplateResponse("home/index.html", {"request": request, "email": user.email})
            session_key = create_session_key()
            web_session[session_key] = user.email
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
            'msg': app_login_data.errors
        }

    user: User = get_user_by_email(app_login_data.email, db=db)
    if user:
        print(user)
        if user.fail_counter >= 3:
            return {
                'errorCode': -1,
                'msg': 'You entered the incorrect password more than three times'
            }
        check_password = Hasher.verify_password(app_login_data.password, user.hashed_password) \
                         and OTP.verify_otp(user.secret, app_login_data.token)

        if not check_password:
            user.fail_counter += 1
            db.commit()
            return {
                'errorCode': -1,
                'msg': 'Incorrect Credentials'
            }
            # add fail counter
    else:
        app_login_data.__dict__.get("errors").append("Incorrect Credentials")
        return {
            'errorCode': -1,
            'msg': app_login_data.errors
        }

    if user.fail_counter > 0:
        user.fail_counter = 0
        db.commit()
    session_id = create_session_key()
    rest_session[app_login_data.email] = session_id
    contact_list.add(json.dumps({
        'email': app_login_data.email,
        'hash_id': user.hash_id,
        'ip_address': app_login_data.ip_address,
        'rsa_public_key': app_login_data.rsa_public_key
    }))

    print(rest_session)
    return {
        'errorCode': 0,
        'msg': 'Success',
        'session_id': session_id
    }


def make_ret(code, msg):
    return {
        'errorCode': code,
        'msg': msg
    }


def check_session(email, session_id):
    if email not in rest_session.keys():
        return False, make_ret(-1, 'not logged in')

    if rest_session[email] != session_id:
        return False, make_ret(-1, 'invalid connection')

    return True, {}


@router.get('/contacts')
async def get_contacts(email, session_id):
    check_valid, err = check_session(email, session_id)
    if not check_valid:
        return err

    return make_ret(0, [json.loads(j) for j in contact_list])


@router.post('/contacts')
async def get_contacts(email, session_id):
    check_valid, err = check_session(email, session_id)
    if not check_valid:
        return err

    return make_ret(0, [json.loads(j) for j in contact_list])
