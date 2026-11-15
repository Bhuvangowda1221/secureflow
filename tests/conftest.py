"""
SecureFlow Test Suite — conftest.py
Provides Flask test client and seeded database for all tests.
"""
import pytest
from app import create_app, db as _db
from app.models.user import User
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.security_policy import SecurityPolicy


@pytest.fixture(scope="session")
def app():
    """Create application configured for testing."""
    test_app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key",
        "ADMIN_EMAIL": "admin@test.local",
        "ADMIN_PASSWORD": "TestAdmin123!",
    })
    return test_app


@pytest.fixture(scope="function")
def db(app):
    """Create database tables and seed test data, clean up after each test."""
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture(scope="function")
def client(app, db):
    """Create a test client with a fresh request context."""
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture(scope="function")
def admin_user(app, db):
    """Return the seeded admin user."""
    with app.app_context():
        user = User.query.filter_by(email="admin@test.local").first()
        if not user:
            user = User(username="testadmin", email="admin@test.local",
                        role="admin", is_active=True)
            user.set_password("TestAdmin123!")
            _db.session.add(user)
            _db.session.commit()
        return user.id  # return ID, not ORM object (session-safe)


@pytest.fixture(scope="function")
def regular_user(app, db):
    """Create and return a regular test user."""
    with app.app_context():
        user = User(username="testuser", email="testuser@test.local",
                    role="user", is_active=True)
        user.set_password("TestUser123!")
        _db.session.add(user)
        _db.session.commit()
        return user.id


@pytest.fixture(scope="function")
def auth_client(client, app, admin_user):
    """Test client logged in as admin."""
    # Use the test client's session directly without extra app_context
    with client.session_transaction() as sess:
        sess["_user_id"] = str(admin_user)
        sess["_fresh"] = True
    return client


@pytest.fixture(scope="function")
def sample_repo(app, db, admin_user):
    """Create a sample repository for testing."""
    with app.app_context():
        repo = Repository(
            name="testowner/testrepo",
            url="https://github.com/testowner/testrepo",
            owner_id=admin_user,
            default_branch="main",
        )
        _db.session.add(repo)
        _db.session.commit()
        return repo.id
