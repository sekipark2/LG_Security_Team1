import base64
import os
import smtplib
import ssl
from email.message import EmailMessage
from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from core.hashing import Hasher
from database.models.users import User
from database.session import get_db
from routers.resetpw.forms import ResetPwForm, ForgetPwForm
from core.memo import password_reset_code, account_activation_code
from sqlalchemy.exc import IntegrityError

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)

# Define email sender and receiver
email_sender = 'lgesecuteam1@gmail.com'
email_password = 'imfzqouxcvsdujru'
email_receiver = ''


def send_password_reset_code(email):
    code = base64.b32encode(os.urandom(4)).decode('utf-8')
    # verify_code[email] = code
    password_reset_code[code] = email

    subject = 'Your password reset code'
    body = "Your password reset code is %s. " % code
    body += "Please go to http://127.0.0.1:8000/resetpw to reset your password"

    print(email, subject, body)

    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email
    em['Subject'] = subject
    em.set_content(body)

    # Add SSL (layer of security)
    context = ssl.create_default_context()

    # Log in and send the email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email, em.as_string())


@router.get("/resetpw/")
def resetpassword(request: Request):
    return templates.TemplateResponse("resetpw/resetpw.html", {"request": request})


@router.post("/resetpw/")
async def resetpassword(request: Request, db: Session = Depends(get_db)):
    form = ResetPwForm(request)
    await form.load_data()
    if await form.is_valid():
        if form.code not in password_reset_code:
            form.__dict__.get("errors").append("Don't mess with us buddy")
            return templates.TemplateResponse("resetpw/resetpw.html", form.__dict__)
        user_email = password_reset_code[form.code]
        try:
            user = db.query(User).filter(User.email == user_email).first()
            if user is None:
                form.__dict__.get("errors").append("Don't mess with us buddy")
                return templates.TemplateResponse("resetpw/resetpw.html", form.__dict__)
            user.hashed_password = Hasher.get_password_hash(form.password)
            db.commit()
            response = templates.TemplateResponse("home/index.html", {"request": request, "email": user.email})
            return response
        except IntegrityError:
            form.__dict__.get("errors").append("Don't mess with us buddy")
            return templates.TemplateResponse("resetpw/resetpw.html", form.__dict__)
    return templates.TemplateResponse("resetpw/resetpw.html", form.__dict__)


@router.get("/forgetpw/")
def forgetpassword(request: Request):
    return templates.TemplateResponse("resetpw/forgetpw.html", {"request": request})


@router.post("/forgetpw/")
async def forgetpassword(request: Request, db: Session = Depends(get_db)):
    form = ForgetPwForm(request)
    await form.load_data()
    if await form.is_valid():
        try:
            user = db.query(User).filter(User.email == form.email).first()
            if user is None:
                form.__dict__.get("errors").append("Don't mess with us buddy")
                return templates.TemplateResponse("resetpw/forgetpw.html", form.__dict__)

            send_password_reset_code(user.email)

            response = {"msg": "please check your email for password reset code"}
            return response
        except IntegrityError:
            form.__dict__.get("errors").append("Don't mess with us buddy")
            return templates.TemplateResponse("resetpw/forgetpw.html", form.__dict__)
    return templates.TemplateResponse("resetpw/forgetpw.html", form.__dict__)


@router.get("/active/{code}")
async def active_account(code: str, db: Session = Depends(get_db)):
    if len(code) == 8:
        if code not in account_activation_code:
            return {"msg": "don't mess with us buddy"}
        user_email = account_activation_code[code]
        try:
            user = db.query(User).filter(User.email == user_email).first()
            if user is None:
                return {"msg": "don't mess with us buddy"}
            user.verified = True
            db.commit()
            return {"msg": "your account has been activated"}
        except IntegrityError:
            return {"msg": "don't mess with us buddy"}
    return {"msg": "don't mess with us buddy"}
