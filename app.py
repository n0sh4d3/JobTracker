from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
import os
import hashlib
import base64
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///job_hunt.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    pet_name = db.Column(db.String(100), nullable=False)
    birth_city = db.Column(db.String(100), nullable=False)
    favorite_movie = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def check_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash
    
    def set_password(self, password):
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=date.today)
    applications_sent = db.Column(db.Integer, default=0)
    networking_contacts = db.Column(db.Integer, default=0)
    skill_practice_hours = db.Column(db.Float, default=0.0)
    research_companies = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'applications_sent': self.applications_sent,
            'networking_contacts': self.networking_contacts,
            'skill_practice_hours': self.skill_practice_hours,
            'research_companies': self.research_companies
        }

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # daily, weekly
    applications_target = db.Column(db.Integer, default=0)
    networking_target = db.Column(db.Integer, default=0)
    skill_hours_target = db.Column(db.Float, default=0.0)
    research_target = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'applications_target': self.applications_target,
            'networking_target': self.networking_target,
            'skill_hours_target': self.skill_hours_target,
            'research_target': self.research_target
        }

# simple token authentication
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        try:
            token = token.replace('Bearer ', '')
            decoded = base64.b64decode(token).decode('utf-8')
            # split only on first colon to handle timestamp colons
            username, timestamp = decoded.split(':', 1)
            
            # simple check - for testing, we'll be more lenient
            # in production you'd want proper datetime parsing
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({'error': 'Invalid token'}), 401
                
            request.current_user = user
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
    return decorated_function

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    user = User(
        username=data['username'],
        pet_name=data['security_questions']['pet_name'].lower(),
        birth_city=data['security_questions']['birth_city'].lower(),
        favorite_movie=data['security_questions']['favorite_movie'].lower()
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user:
        print(f"User found: {user.username}")
        print(f"Stored hash: {user.password_hash}")
        input_hash = hashlib.sha256(data['password'].encode()).hexdigest()
        print(f"Input hash: {input_hash}")
        print(f"Password check result: {user.check_password(data['password'])}")
        
        if user.check_password(data['password']):
            # create simple token
            token_data = f"{user.username}:{datetime.now().isoformat()}"
            token = base64.b64encode(token_data.encode()).decode('utf-8')
            return jsonify({'token': token, 'username': user.username})
    else:
        print(f"User not found: {data['username']}")
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/verify-user', methods=['POST'])
def verify_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if user:
        return jsonify({'message': 'User found'}), 200
    else:
        return jsonify({'error': 'Username not found'}), 404

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if not user:
        return jsonify({'error': 'Username not found'}), 404
    
    # verify security questions
    answers = data['security_answers']
    if (user.pet_name != answers['pet_name'].lower() or
        user.birth_city != answers['birth_city'].lower() or
        user.favorite_movie != answers['favorite_movie'].lower()):
        return jsonify({'error': 'Security questions do not match'}), 400
    
    # update password
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({'message': 'Password reset successfully'}), 200

@app.route('/api/activities', methods=['GET'])
@require_auth
def get_activities():
    days = request.args.get('days', 30, type=int)
    start_date = date.today() - timedelta(days=days)
    activities = Activity.query.filter(
        Activity.user_id == request.current_user.id,
        Activity.date >= start_date
    ).order_by(Activity.date.desc()).all()
    return jsonify([activity.to_dict() for activity in activities])

@app.route('/api/activities', methods=['POST'])
@require_auth
def add_activity():
    data = request.get_json()
    
    # check if activity exists for today
    today = date.today()
    existing = Activity.query.filter_by(
        user_id=request.current_user.id,
        date=today
    ).first()
    
    if existing:
        existing.applications_sent += data.get('applications_sent', 0)
        existing.networking_contacts += data.get('networking_contacts', 0)
        existing.skill_practice_hours += data.get('skill_practice_hours', 0.0)
        existing.research_companies += data.get('research_companies', 0)
        activity = existing
    else:
        activity = Activity(
            user_id=request.current_user.id,
            applications_sent=data.get('applications_sent', 0),
            networking_contacts=data.get('networking_contacts', 0),
            skill_practice_hours=data.get('skill_practice_hours', 0.0),
            research_companies=data.get('research_companies', 0)
        )
        db.session.add(activity)
    
    db.session.commit()
    return jsonify(activity.to_dict()), 201

@app.route('/api/goals', methods=['GET'])
@require_auth
def get_goals():
    goals = Goal.query.filter_by(
        user_id=request.current_user.id,
        active=True
    ).all()
    return jsonify([goal.to_dict() for goal in goals])

@app.route('/api/goals', methods=['POST'])
@require_auth
def set_goals():
    data = request.get_json()
    
    # deactivate existing goals of same type
    Goal.query.filter_by(
        user_id=request.current_user.id,
        type=data['type'],
        active=True
    ).update({'active': False})
    
    goal = Goal(
        user_id=request.current_user.id,
        type=data['type'],
        applications_target=data.get('applications_target', 0),
        networking_target=data.get('networking_target', 0),
        skill_hours_target=data.get('skill_hours_target', 0.0),
        research_target=data.get('research_target', 0)
    )
    
    db.session.add(goal)
    db.session.commit()
    return jsonify(goal.to_dict()), 201

@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    today = date.today()
    week_start = today - timedelta(days=today.weekday())
    
    # today's activity
    today_activity = Activity.query.filter_by(
        user_id=request.current_user.id,
        date=today
    ).first()
    today_total = 0
    if today_activity:
        today_total = (today_activity.applications_sent + 
                      today_activity.networking_contacts + 
                      today_activity.research_companies)
    
    # this week's activities
    week_activities = Activity.query.filter(
        Activity.user_id == request.current_user.id,
        Activity.date >= week_start
    ).all()
    week_total = sum(
        a.applications_sent + a.networking_contacts + a.research_companies 
        for a in week_activities
    )
    
    # streak calculation
    streak = 0
    check_date = today
    while True:
        day_activity = Activity.query.filter_by(
            user_id=request.current_user.id,
            date=check_date
        ).first()
        if day_activity and (day_activity.applications_sent > 0 or 
                           day_activity.networking_contacts > 0 or 
                           day_activity.research_companies > 0):
            streak += 1
            check_date -= timedelta(days=1)
        else:
            break
    
    total_days = Activity.query.filter_by(user_id=request.current_user.id).count()
    
    return jsonify({
        'today_activities': today_total,
        'week_activities': week_total,
        'current_streak': streak,
        'total_days_logged': total_days
    })

@app.route('/api/debug-user/<username>')
def debug_user(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({
            'username': user.username,
            'password_hash': user.password_hash,
            'pet_name': user.pet_name,
            'birth_city': user.birth_city,
            'favorite_movie': user.favorite_movie
        })
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
