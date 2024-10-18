from typing import Annotated
from fastapi import Depends, Form
from x_auth import AuthFailReason, AuthException
from x_auth.backend import AuthBackend as BaseAuthBackend
from x_auth.pydantic import Token, AuthUser

from pswd_auth.models import User
from pswd_auth.pydantic import UserReg


class PasswordRequestForm:
    """This is a dependency class to collect the `username` and `password` as form data for an password auth flow."""

    def __init__(self, username: Annotated[str, Form()], password: Annotated[str, Form()]):
        self.username = username
        self.password = password


class AuthBackend(BaseAuthBackend):
    # API ENDOINTS
    # api reg endpoint
    async def reg(self, user_reg_input: UserReg) -> Token:
        return await super().reg(user_reg_input)

    # login for api endpoint
    async def login_for_access_token(self, form_data: Annotated[PasswordRequestForm, Depends()]) -> Token:
        async def authenticate_user(username: str, password: str) -> AuthUser:
            user_db: User = await self.db_user_model.get_or_none(username=username)
            if user_db:
                data = AuthUser.model_validate(user_db, from_attributes=True)
                if user_db.pwd_vrf(password):
                    return data
                reason = AuthFailReason.password
            else:
                reason = AuthFailReason.username
            raise AuthException(reason)

        user = await authenticate_user(form_data.username, form_data.password)
        return self._user2tok(user)
