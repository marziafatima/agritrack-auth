"""Automated tests for the Sign Up / Sign In module (run with: python -m pytest)."""
import os
import secrets

os.environ["ADMIN_PASSWORD"] = "Admin12345"  # test-only password, not a real one

import pytest

import app as agritrack

ADMIN_PW = "Admin12345"
USER_PW = "Farmer123"


@pytest.fixture
def client():
    agritrack.FAILED_LOGINS.clear()
    return agritrack.app.test_client()


def post(client, url, **data):
    """POST a form with a valid CSRF token."""
    with client.session_transaction() as sess:
        sess["_csrf"] = "test-token"
    data["_csrf"] = "test-token"
    return client.post(url, data=data)


def new_username():
    return "user_" + secrets.token_hex(3)


def sign_up(client, username, role="Farmer"):
    return post(client, "/register", name="Test User", username=username, password=USER_PW,
                role=role, phone="0300-1234567", location="Multan")


def get_status(username):
    with agritrack.app.app_context():
        user = agritrack.User.query.filter_by(username=username).first()
        return user.status if user else None


def admin_set(client, username, action):
    with agritrack.app.app_context():
        uid = agritrack.User.query.filter_by(username=username).first().id
    post(client, "/login", username="admin", password=ADMIN_PW)
    post(client, f"/admin/{uid}/{action}")
    client.post("/logout", data={"_csrf": "test-token"})


def test_healthz(client):
    assert client.get("/healthz").data == b"ok"


def test_sign_up_creates_pending_user(client):
    name = new_username()
    response = sign_up(client, name)
    assert response.status_code == 302
    assert get_status(name) == "Pending"


def test_sign_up_rejects_weak_password(client):
    name = new_username()
    response = post(client, "/register", name="Test User", username=name, password="short",
                    role="Farmer", phone="0300-1234567", location="Multan")
    assert response.status_code == 200
    assert get_status(name) is None


def test_cannot_register_as_admin(client):
    name = new_username()
    sign_up(client, name, role="Admin")
    assert get_status(name) is None


def test_post_without_csrf_token_is_rejected(client):
    assert client.post("/login", data={"username": "admin", "password": ADMIN_PW}).status_code == 400


def test_pending_user_cannot_log_in(client):
    name = new_username()
    sign_up(client, name)
    response = post(client, "/login", username=name, password=USER_PW)
    assert b"waiting for Admin" in response.data


def test_admin_verify_then_login_works(client):
    name = new_username()
    sign_up(client, name)
    admin_set(client, name, "verify")
    assert get_status(name) == "Active"
    response = post(client, "/login", username=name, password=USER_PW)
    assert response.status_code == 302 and response.headers["Location"].endswith("/dashboard")


def test_blocked_user_cannot_log_in(client):
    name = new_username()
    sign_up(client, name)
    admin_set(client, name, "verify")
    admin_set(client, name, "block")
    assert get_status(name) == "Blocked"
    response = post(client, "/login", username=name, password=USER_PW)
    assert b"blocked" in response.data


def test_wrong_password_shows_generic_message(client):
    response = post(client, "/login", username="admin", password="wrong-password")
    assert b"Wrong username or password" in response.data


def test_login_locked_after_five_wrong_passwords(client):
    for _ in range(5):
        post(client, "/login", username="admin", password="wrong-password")
    response = post(client, "/login", username="admin", password=ADMIN_PW)
    assert response.status_code == 200
    assert b"Too many wrong attempts" in response.data


def test_normal_user_cannot_open_admin_panel(client):
    name = new_username()
    sign_up(client, name)
    admin_set(client, name, "verify")
    post(client, "/login", username=name, password=USER_PW)
    assert client.get("/admin").status_code == 403
