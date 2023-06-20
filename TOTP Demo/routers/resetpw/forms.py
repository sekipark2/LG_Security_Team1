import re
from typing import List
from typing import Optional

from fastapi import Request


regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'


class ResetPwForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.code: Optional[str] = None
        self.password: Optional[str] = None
        self.confirmPassword: Optional[str] = None

    async def load_data(self):
        form = await self.request.form()
        self.code = form.get("code")
        self.password = form.get("password")
        self.confirmPassword = form.get("confirm_password")

    async def is_valid(self):
        # if not re.fullmatch(regex, self.email):
        #     self.errors.append("Please enter valid email")
        if not self.code or not len(self.code) == 8:
            self.errors.append("Invalid password reset token")
        if not self.password or not len(self.password) >= 10:
            self.errors.append("Password must be > 10 chars")
        if self.password and re.search(r"\d", self.password) is None:
            self.errors.append("Password must include one number")
        if self.password and re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', self.password) is None:
            self.errors.append("Password must include one symbol number")
        if self.password != self.confirmPassword:
            self.errors.append("Confirm Password does not match")
        if not self.errors:
            return True
        return False


class ForgetPwForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.email: Optional[str] = None

    async def load_data(self):
        form = await self.request.form()
        self.email = form.get("email")

    async def is_valid(self):
        if not re.fullmatch(regex, self.email):
            self.errors.append("Please enter valid email")
        if not self.errors:
            return True
        return False
