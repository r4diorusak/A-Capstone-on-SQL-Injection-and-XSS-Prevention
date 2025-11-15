import pytest
from app import app, db, User

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Use a temporary database
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        # create sample users
        u1 = User(username='alice')
        u1.set_password('alicepass')
        u2 = User(username='bob')
        u2.set_password('bobpass')
        db.session.add_all([u1, u2])
        db.session.commit()
    with app.test_client() as client:
        yield client

def test_sql_injection_search(client):
    # Attempt SQL injection payload in query parameter
    payload = "' OR 1=1 --"
    rv = client.get(f"/search?q={payload}")
    data = rv.get_data(as_text=True)
    # Should not return all users; payload treated as literal string
    assert 'alice' not in data
    assert 'bob' not in data

def test_xss_user_display_escaped(client):
    # Insert a user with XSS in username
    with app.app_context():
        x = User(username='<script>alert(1)</script>')
        x.set_password('x')
        db.session.add(x)
        db.session.commit()
    rv = client.get('/search?q=script')
    data = rv.get_data(as_text=True)
    # Raw script tag should be escaped in the output
    assert '<script>alert(1)</script>' not in data
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in data
