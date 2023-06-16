from pydantic import BaseModel


class UserCreate(BaseModel):
    email: str
    password: str
    secret: str
    verified: bool
    fail_counter: int


class ShowUser(BaseModel):
    email: str

    class Config:
        orm_mode = True
