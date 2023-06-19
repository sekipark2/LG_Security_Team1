from pydantic import BaseModel


class UserCreate(BaseModel):
    email: str
    password: str
    secret: str
    verified: bool
    fail_counter: int
    first_name: str
    last_name: str
    address: str


class ShowUser(BaseModel):
    email: str
    first_name: str
    last_name: str

    class Config:
        orm_mode = True
