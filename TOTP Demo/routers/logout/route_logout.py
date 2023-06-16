import routers.login.route_login
from fastapi import APIRouter
from fastapi import Request, Response
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse

templates = Jinja2Templates(directory="templates")
router = APIRouter(include_in_schema=True)

web_session = routers.login.route_login.web_session


@router.get("/logout/")
def logout(request: Request):
    session_id = request.cookies.get('login_session')
    print('login_session', session_id)

    response = RedirectResponse("/login")
    if not session_id or session_id not in web_session.keys():
        return response

    if session_id:
        print(web_session[session_id], 'log out')
        web_session.pop(session_id)
        response.delete_cookie('login_session')
    return response

