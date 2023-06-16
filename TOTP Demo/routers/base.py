from fastapi import APIRouter
from routers.login import route_login
from routers.signup import route_signup
from routers.logout import route_logout
from routers.home import route_home

api_router = APIRouter()
api_router.include_router(route_signup.router, prefix="", tags=["users-webapp"])
api_router.include_router(route_login.router, prefix="", tags=["auth-webapp"])
api_router.include_router(route_logout.router, prefix="", tags=["auth-webapp"])
api_router.include_router(route_home.router, prefix="", tags=["auth-webapp"])