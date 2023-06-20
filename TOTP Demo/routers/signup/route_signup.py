import base64
from io import BytesIO
import os
from database.repository.users import create_new_user
from database.session import get_db
from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request
from fastapi.templating import Jinja2Templates
from schemas.users import UserCreate
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from routers.signup.forms import UserCreateForm
import pyqrcode
import png
import smtplib
import ssl
from email.message import EmailMessage
import time
from core.hashing import Hasher
from core.memo import account_activation_code

# Define email sender and receiver
email_sender = 'lgesecuteam1@gmail.com'
email_password = 'imfzqouxcvsdujru'
email_receiver = ''

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)

verify_code = {}


def send_verify_mail(email):
    code = base64.b32encode(os.urandom(4)).decode('utf-8')
    # verify_code[email] = code
    account_activation_code[code] = email

    subject = 'Test for OTP'
    # body = "Your account activation code is '%s'" % code
    body = "Please go to http://127.0.0.1/active/%s to activate your account" % code

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


@router.get("/signup/")
def register(request: Request):
    return templates.TemplateResponse("signup/signup.html", {"request": request})


@router.get("/qrcode")
def register(email):
    # send_verify_mail(email)
    return templates.TemplateResponse("qrcode/qrcode.html", {"request": request})


@router.post("/signup/")
async def register(request: Request, db: Session = Depends(get_db)):
    form = UserCreateForm(request)
    await form.load_data()
    if await form.is_valid():
        user = UserCreate(
            email=form.email,
            password=form.password,
            secret=base64.b32encode(os.urandom(10)).decode('utf-8'),
            verified=False,
            fail_counter=0,
            first_name=form.first_name,
            last_name=form.last_name,
            address=form.address
        )
        print('first_name', form.first_name)
        try:
            user = create_new_user(user=user, db=db)
            data = 'otpauth://totp/LG-Secu-Team1:{0}?secret={1}&issuer=LG-Secu-Team1' \
            .format(user.email, user.secret)
            send_verify_mail(user.email)
            url = pyqrcode.create(data)
            stream = BytesIO()
            url.png(stream, scale=3)
            return templates.TemplateResponse("qrcode/qrcode.html", {"request": request, "data": base64.b64encode(stream.getvalue()).decode('utf-8')})
            #
        except IntegrityError as e:
            print(e)
            form.__dict__.get("errors").append("Duplicate username or email")
            return templates.TemplateResponse("signup/signup.html", form.__dict__)
    return templates.TemplateResponse("signup/signup.html", form.__dict__)