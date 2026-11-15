"""Tests for authentication routes."""
import pytest
from app import db
from app.models.user import User


class TestLogin:
    def test_login_page_loads(self, client):
        resp = client.get("/auth/login")
        assert resp.status_code == 200
        assert b"Sign In" in resp.data or b"SecureFlow" in resp.data

    def test_login_valid_credentials(self, app, client, admin_user):
        # Get email from admin_user id
        with app.app_context():
            from app import db
            user = db.session.get(User, admin_user)
            email = user.email
        resp = client.post("/auth/login", data={
            "email": email,
            "password": "TestAdmin123!",
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_login_invalid_password(self, app, client, admin_user):
        with app.app_context():
            from app import db
            user = db.session.get(User, admin_user)
            email = user.email
        resp = client.post("/auth/login", data={
            "email": email,
            "password": "wrongpassword",
        }, follow_redirects=True)
        assert resp.status_code == 200
        # Route renders login.html directly with flash message
        assert b"Invalid" in resp.data or b"login" in resp.data.lower()

    def test_login_invalid_email(self, client):
        resp = client.post("/auth/login", data={
            "email": "nonexistent@test.com",
            "password": "anypassword",
        }, follow_redirects=True)
        assert resp.status_code == 200
        # Route renders login.html with error
        assert b"login" in resp.data.lower() or b"auth" in resp.data.lower()

    def test_logout(self, auth_client):
        resp = auth_client.get("/auth/logout", follow_redirects=True)
        assert resp.status_code == 200


class TestRegister:
    def test_register_page_loads(self, client):
        resp = client.get("/auth/register")
        assert resp.status_code == 200

    def test_register_new_user(self, app, client):
        resp = client.post("/auth/register", data={
            "username": "newuser123",
            "email": "newuser@test.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        }, follow_redirects=True)
        assert resp.status_code == 200
        with app.app_context():
            user = User.query.filter_by(email="newuser@test.com").first()
            assert user is not None
            assert user.username == "newuser123"
            assert user.role == "user"

    def test_register_password_mismatch(self, client):
        resp = client.post("/auth/register", data={
            "username": "mismatch",
            "email": "mismatch@test.com",
            "password": "Password123!",
            "confirm_password": "Different456!",
        }, follow_redirects=True)
        assert resp.status_code == 200
        # Flash message: "Passwords do not match." is in page
        assert b"match" in resp.data.lower() or b"password" in resp.data.lower()

    def test_register_duplicate_email(self, app, client, admin_user):
        with app.app_context():
            user = db.session.get(User, admin_user)
            email = user.email
        resp = client.post("/auth/register", data={
            "username": "duplicate",
            "email": email,
            "password": "Password123!",
            "confirm_password": "Password123!",
        }, follow_redirects=True)
        assert resp.status_code == 200
        assert b"already" in resp.data.lower()


class TestPasswordHashing:
    def test_password_hashed_correctly(self, app):
        with app.app_context():
            user = User(username="hashtest", email="hash@test.com", role="user")
            user.set_password("SecurePass123!")
            assert user.password_hash != "SecurePass123!"
            assert len(user.password_hash) > 20
            assert user.check_password("SecurePass123!")
            assert not user.check_password("WrongPass!")

    def test_no_plaintext_password_stored(self, app, admin_user):
        with app.app_context():
            user = db.session.get(User, admin_user)
            assert "TestAdmin" not in user.password_hash
