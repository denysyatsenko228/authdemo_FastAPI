# FastAPI Server
import base64
import hmac
import hashlib
import json
from typing import Optional

from fastapi import FastAPI, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "44d157549069f15e1447e94eab119882c3edbc098d31f08a88e5fdc2686842b0"
PASSWORD_SALT = "3df3e222b229c1c8c3d2a4af093ba2f42b9f34cd1ed5206a37a5f696253bb2f0"


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return (
        hmac.new(SECRET_KEY.encode(), msg=data.encode(), digestmod=hashlib.sha256)
        .hexdigest()
        .upper()
    )


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = (
        hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    )
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users = {
    "alexey@gmail.com": {
        "name": "Алексей",
        "password": "693d120a92d9446bda7e03f942c5d8ff76e8ca56830954c30da8c6e0bfb31dc9",
        "balance": 100_000,
    },
    "petr@user.com": {
        "name": "Петр",
        "password": "8bb94412970f2cd44af10473eeb43173240da491082e96e01fba4963b5169563",
        "balance": 20_000,
    },
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}",
        media_type="text/html",
    )


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({"success": False, "message": "Я вас не знаю!"}),
            media_type="application/json",
        )

    response = Response(
        json.dumps(
            {
                "success": True,
                "message": f"Привет, {user['name']}!<br /> Баланс: {user['balance']}",
            }
        ),
        media_type="application/json",
    )

    username_signed = (
        base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    )
    response.set_cookie(key="username", value=username_signed)
    return response
