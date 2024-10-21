from typing import Annotated
from fastapi import Depends, Form
from fastapi.openapi.models import OAuth2, OAuthFlows, OAuthFlowPassword
from x_auth import AuthFailReason, AuthException, Security
from x_auth.router import AuthRouter as BaseRouter
from x_auth.pydantic import Token, AuthUser

from pswd_auth.model import User
from pswd_auth.pydantic import UserReg


class PasswordRequestForm:
    """This is a dependency class to collect the `username` and `password` as form data for an password auth flow."""

    def __init__(self, username: Annotated[str, Form()], password: Annotated[str, Form()]):
        self.username = username
        self.password = password


class PswdScheme(Security):
    """HTTP Bearer token authentication"""

    def __init__(self, token_path: str = "token", auto_error: bool = False, scheme_name: str = None):
        flows = OAuthFlows(password=OAuthFlowPassword(tokenUrl="/" + token_path))
        mdl = OAuth2(flows=flows)
        super().__init__(mdl, auto_error, scheme_name)


class AuthRouter(BaseRouter):
    token_path = "token"

    def __init__(self, secret: str, db_user_model: type(User) = User):
        super().__init__(secret, db_user_model, PswdScheme(token_path=self.token_path))
        self.routes[self.token_path] = self.login_for_access_token, "POST"

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
