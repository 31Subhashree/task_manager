import secrets
from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from logging.handlers import RotatingFileHandler
import logging
from flask import Flask, redirect, url_for
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = secrets.token_urlsafe(32)  # Use a strong, randomly generated secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# Setup logging
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=1)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

# Define Task model
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    task = db.Column(db.String(255), nullable=False)

# Manually create application context
with app.app_context():
    # Create the database tables
    db.create_all()

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            return jsonify({"msg": "Username and password are required"}), 400
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "User created successfully"}), 200
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.json.get('username')
        password = request.json.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({"msg": "Invalid credentials"}), 401
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    return render_template('login.html')

@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user = get_jwt_identity()
    user_tasks = Task.query.filter_by(username=current_user).all()
    tasks = [{'username': task.username, 'task': task.task} for task in user_tasks]
    return render_template('tasks.html', tasks=tasks)

# Route for adding/editing task
@app.route('/tasks/<int:task_id>', methods=['GET', 'POST'])
@jwt_required()
def add_edit_task(task_id=None):
    current_user = get_jwt_identity()
    if request.method == 'POST':
        task_content = request.form['task']
        if task_id:
            # Edit existing task
            task = Task.query.filter_by(id=task_id, username=current_user).first()
            if not task:
                return jsonify({"msg": "Task not found"}), 404
            task.task = task_content
            db.session.commit()
            app.logger.info(f"Task edited by {current_user}: {task_content}")
        else:
            # Add new task
            new_task = Task(username=current_user, task=task_content)
            db.session.add(new_task)
            db.session.commit()
            app.logger.info(f"Task added by {current_user}: {task_content}")
        return redirect('/tasks')
    
    # If method is GET, render the form
    task = Task.query.filter_by(id=task_id, username=current_user).first() if task_id else None
    action = 'Edit' if task_id else 'Add'
    url = f'/tasks/{task_id}' if task_id else '/tasks'
    task_content = task.task if task else ''
    return render_template('add_edit_task.html', action=action, url=url, task_content=task_content)

# Delete Task
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user = get_jwt_identity()
    task = Task.query.filter_by(id=task_id, username=current_user).first()
    if not task:
        return jsonify({"msg": "Task not found"}), 404

    db.session.delete(task)
    db.session.commit()
    app.logger.info(f"Task deleted by {current_user}: {task.task}")
    return jsonify({"msg": "Task deleted successfully"}), 200

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
