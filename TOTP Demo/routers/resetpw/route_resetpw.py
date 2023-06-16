from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from core.hashing import Hasher
from database.models.users import User
from database.session import get_db
from routers.resetpw.forms import ResetPwForm, ForgetPwForm
from routers.signup.route_signup import verify_code
from sqlalchemy.exc import IntegrityError

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)


@router.get("/resetpw/")
def resetpassword(request: Request):
    return templates.TemplateResponse("resetpw/resetpw.html", {"request": request})


@router.post("/resetpw/")
async def resetpassword(request: Request, db: Session = Depends(get_db)):
    print(verify_code)
    form = ResetPwForm(request)
    await form.load_data()
    if await form.is_valid():
        if form.code not in verify_code:
            form.__dict__.get("errors").append("Don't mess with us buddy")
            return templates.TemplateResponse("resetpw/resetpw.html", form.__dict__)
        user_email = verify_code[form.code]
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
            verify_code['123456'] = form.email # random long uuid4 code
            print(verify_code)
            # send verify_code[form.email]
            response = {"msg": "please check your email for password reset code"}
            return response
        except IntegrityError:
            form.__dict__.get("errors").append("Don't mess with us buddy")
            return templates.TemplateResponse("resetpw/forgetpw.html", form.__dict__)
    return templates.TemplateResponse("resetpw/forgetpw.html", form.__dict__)
