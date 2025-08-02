import pytest
import json
import base64
from datetime import date, timedelta, datetime
from app import app, db, Activity, Goal, User

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            
            # create test user
            user = User(
                username='testuser',
                pet_name='fluffy',
                birth_city='london',
                favorite_movie='matrix'
            )
            user.set_password('testpass')
            db.session.add(user)
            db.session.commit()
            
            yield client
            db.drop_all()

@pytest.fixture
def auth_headers(client):
    # login and get real token
    data = {
        'username': 'testuser',
        'password': 'testpass'
    }
    
    response = client.post('/api/login',
                          data=json.dumps(data),
                          content_type='application/json')
    
    result = json.loads(response.data)
    token = result['token']
    return {'Authorization': f'Bearer {token}'}

def test_login_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'JobTracker Pro' in response.data

def test_dashboard_page(client):
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'Dashboard' in response.data

def test_register_user(client):
    data = {
        'username': 'newuser',
        'password': 'newpass',
        'security_questions': {
            'pet_name': 'buddy',
            'birth_city': 'paris',
            'favorite_movie': 'avatar'
        }
    }
    
    response = client.post('/api/register',
                          data=json.dumps(data),
                          content_type='application/json')
    
    assert response.status_code == 201
    result = json.loads(response.data)
    assert result['message'] == 'User created successfully'

def test_login_user(client):
    data = {
        'username': 'testuser',
        'password': 'testpass'
    }
    
    response = client.post('/api/login',
                          data=json.dumps(data),
                          content_type='application/json')
    
    assert response.status_code == 200
    result = json.loads(response.data)
    assert 'token' in result
    assert result['username'] == 'testuser'

def test_add_activity(client, auth_headers):
    data = {
        'applications_sent': 3,
        'networking_contacts': 2,
        'skill_practice_hours': 1.5,
        'research_companies': 4
    }
    
    response = client.post('/api/activities', 
                          data=json.dumps(data),
                          content_type='application/json',
                          headers=auth_headers)
    
    assert response.status_code == 201
    result = json.loads(response.data)
    assert result['applications_sent'] == 3
    assert result['networking_contacts'] == 2

def test_get_activities(client, auth_headers):
    response = client.get('/api/activities',
                         headers=auth_headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)

def test_set_goals(client, auth_headers):
    data = {
        'type': 'daily',
        'applications_target': 5,
        'networking_target': 3,
        'skill_hours_target': 2.0,
        'research_target': 4
    }
    
    response = client.post('/api/goals',
                          data=json.dumps(data),
                          content_type='application/json',
                          headers=auth_headers)
    
    assert response.status_code == 201
    result = json.loads(response.data)
    assert result['applications_target'] == 5

def test_get_stats(client, auth_headers):
    response = client.get('/api/stats',
                         headers=auth_headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'today_activities' in data
    assert 'current_streak' in data

def test_unauthorized_access(client):
    response = client.get('/api/activities')
    assert response.status_code == 401
    
    response = client.get('/api/stats')
    assert response.status_code == 401

def test_verify_user(client):
    # test existing user
    response = client.post('/api/verify-user',
                          data=json.dumps({'username': 'testuser'}),
                          content_type='application/json')
    assert response.status_code == 200
    
    # test non-existing user
    response = client.post('/api/verify-user',
                          data=json.dumps({'username': 'nonexistent'}),
                          content_type='application/json')
    assert response.status_code == 404

def test_reset_password(client):
    # test successful password reset
    data = {
        'username': 'testuser',
        'security_answers': {
            'pet_name': 'fluffy',
            'birth_city': 'london',
            'favorite_movie': 'matrix'
        },
        'new_password': 'newpassword123'
    }
    
    response = client.post('/api/reset-password',
                          data=json.dumps(data),
                          content_type='application/json')
    assert response.status_code == 200
    
    # verify can login with new password
    login_data = {
        'username': 'testuser',
        'password': 'newpassword123'
    }
    
    response = client.post('/api/login',
                          data=json.dumps(login_data),
                          content_type='application/json')
    assert response.status_code == 200

def test_reset_password_wrong_answers(client):
    # test with wrong security answers
    data = {
        'username': 'testuser',
        'security_answers': {
            'pet_name': 'wrong',
            'birth_city': 'wrong',
            'favorite_movie': 'wrong'
        },
        'new_password': 'newpassword123'
    }
    
    response = client.post('/api/reset-password',
                          data=json.dumps(data),
                          content_type='application/json')
    assert response.status_code == 400
