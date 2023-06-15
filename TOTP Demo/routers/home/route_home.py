from core.hashing import Hasher
from database.session import get_db
from fastapi import APIRouter
from fastapi import Depends
from fastapi import Request
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from routers.home.forms import UserModifyForm
import routers.login.route_login
from fastapi.responses import RedirectResponse
from database.models.users import User
from database.repository.users import get_user_by_email

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)

web_session = routers.login.route_login.web_session

@router.post("/home/")
async def change_user(request: Request, db: Session = Depends(get_db)):
    form = UserModifyForm(request)
    await form.load_data()
    if await form.is_valid():
        session_id = request.cookies.get('login_session')
        print('login_session', session_id)
        if not session_id or session_id not in web_session.keys():
            return RedirectResponse("/login")

        email = web_session[session_id]
        try:
            user: User = get_user_by_email(email, db=db)
            user.email = form.email
            user.hashed_password = Hasher.get_password_hash(form.password)
            db.commit()
            #
        except IntegrityError:
            form.__dict__.get("errors").append("Duplicate username or email")
            return templates.TemplateResponse("home/index.html", form.__dict__)
    return templates.TemplateResponse("home/index.html", form.__dict__)