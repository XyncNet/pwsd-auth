from pydantic import BaseModel

from x_auth.pydantic import UserReg as BaseUserReg


class UserPwd(BaseModel):
    password: str


class UserReg(UserPwd, BaseUserReg):
    pass
