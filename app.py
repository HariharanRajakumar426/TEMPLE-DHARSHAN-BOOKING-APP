from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp
import sqlite3
from datetime import datetime
import logging
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')  # Use env var for production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', 'development') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Session lasts 1 hour

# Set up CSRF protection
csrf = CSRFProtect(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Database initialization
def init_db():
    conn = sqlite3.connect('stories.db')
    c = conn.cursor()

    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('writer', 'reader')) NOT NULL
        )
    ''')

    # Create stories table
    c.execute('''
        CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(author_id) REFERENCES users(id)
        )
    ''')

    # Create likes table
    c.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            story_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(story_id) REFERENCES stories(id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            UNIQUE(story_id, user_id)
        )
    ''')

    # Create comments table
    c.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            story_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(story_id) REFERENCES stories(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

# Initialize database
init_db()

# WTForms for signup and login
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=20), 
        Regexp(r'^[a-zA-Z0-9_]+$', message="Username can only contain letters, numbers, and underscores")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', choices=[('reader', 'Reader'), ('writer', 'Writer')], validators=[DataRequired()])
    submit = SubmitField('Signup')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('stories.db')
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route('/')
def index():
    try:
        logger.debug("Rendering index.html at %s", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        return render_template('index.html', current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        logger.error(f"Error rendering index.html: {e}")
        return "Failed to render the page. Please check the server logs.", 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                     (form.username.data, form.email.data))
            if c.fetchone():
                logger.debug(f"Registration failed: Username {form.username.data} or email {form.email.data} already exists")
                return render_template('signup.html', form=form, error='Username or email already exists')
            
            password_hash = generate_password_hash(form.password.data)
            c.execute('INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                     (form.username.data, form.email.data, password_hash, form.role.data))
            conn.commit()
            logger.debug(f"User {form.username.data} registered successfully")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            logger.error(f"Database error during registration: {e}")
            return render_template('signup.html', form=form, error='Database error')
        finally:
            conn.close()
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('SELECT * FROM users WHERE username = ?', (form.username.data,))
            user = c.fetchone()
            if user and check_password_hash(user['password_hash'], form.password.data):
                session.permanent = True
                session['user_id'] = user['id']
                logger.debug(f"User {form.username.data} logged in successfully with user_id {user['id']}")
                return redirect(url_for('dashboard'))
            logger.debug(f"Login failed for {form.username.data}: Invalid credentials")
            return render_template('login.html', form=form, error='Invalid credentials')
        except sqlite3.Error as e:
            logger.error(f"Database error during login: {e}")
            return render_template('login.html', form=form, error='Database error')
        finally:
            conn.close()
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST'])
def logout():
    logger.debug(f"Logging out, current session: {session}")
    session.pop('user_id', None)
    logger.debug(f"Session after logout: {session}")
    return jsonify({'success': True})

@app.route('/check_session')
def check_session():
    logger.debug(f"Checking session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    if 'user_id' in session:
        conn = get_db_connection()
        c = conn.cursor()
        try:
            c.execute('SELECT id, username, role FROM users WHERE id = ?', (session['user_id'],))
            user = c.fetchone()
            if user:
                logger.debug(f"Session found for user: {user['username']}")
                return jsonify({'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}})
            else:
                logger.debug("No user found for session")
                return jsonify({'user': None})
        except sqlite3.Error as e:
            logger.error(f"Database error during session check: {e}")
            return jsonify({'user': None}), 500
        finally:
            conn.close()
    logger.debug("No session found")
    return jsonify({'user': None})

@app.route('/publish', methods=['POST'])
def publish():
    logger.debug(f"Publish request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    if 'user_id' not in session:
        logger.error("Unauthorized access to publish: No user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not all(key in data for key in ['title', 'content']) or not data['title'].strip() or not data['content'].strip():
        return jsonify({'success': False, 'message': 'Invalid input'}), 400
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO stories (title, content, author_id, timestamp) VALUES (?, ?, ?, ?)',
                 (data['title'], data['content'], session['user_id'], datetime.now()))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        logger.error(f"Database error during publish: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/stories')
def get_stories():
    logger.debug(f"Get stories request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT s.id, s.title, s.content, u.username as author, 
                   COUNT(l.id) as likes, COUNT(c.id) as comment_count,
                   EXISTS(SELECT 1 FROM likes l2 WHERE l2.story_id = s.id AND l2.user_id = ?) as liked
            FROM stories s
            JOIN users u ON s.author_id = u.id
            LEFT JOIN likes l ON s.id = l.story_id
            LEFT JOIN comments c ON s.id = c.story_id
            GROUP BY s.id
            ORDER BY s.timestamp DESC
        ''', (session.get('user_id', 0),))
        stories = [{'id': row['id'], 'title': row['title'], 'content': row['content'], 'author': row['author'], 
                    'likes': row['likes'], 'comment_count': row['comment_count'], 'liked': bool(row['liked'])} for row in c.fetchall()]
        logger.debug(f"Fetched {len(stories)} stories")
        return jsonify(stories)
    except sqlite3.Error as e:
        logger.error(f"Database error in get_stories: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/dashboard')
def dashboard():
    logger.debug(f"Accessing dashboard with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    if 'user_id' not in session:
        logger.error("Unauthorized access to dashboard: No user_id in session")
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        if not user:
            logger.error(f"No user found for user_id: {session['user_id']}")
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        role = user['role']
        logger.debug(f"User role: {role}")
        
        if role == 'writer':
            logger.debug("Fetching stories for writer")
            c.execute('''
                SELECT s.id, s.title, s.content, 
                       COUNT(l.id) as likes, COUNT(c.id) as comment_count
                FROM stories s
                LEFT JOIN likes l ON s.id = l.story_id
                LEFT JOIN comments c ON s.id = c.story_id
                WHERE s.author_id = ?
                GROUP BY s.id
                ORDER BY s.timestamp DESC
            ''', (session['user_id'],))
            stories = [{'id': row['id'], 'title': row['title'], 'content': row['content'], 
                        'likes': row['likes'], 'comment_count': row['comment_count']} for row in c.fetchall()]
        else:
            logger.debug("Fetching stories for reader")
            c.execute('''
                SELECT s.id, s.title, s.content, u.username as author, 
                       COUNT(l.id) as likes, COUNT(c.id) as comment_count,
                       EXISTS(SELECT 1 FROM likes l2 WHERE l2.story_id = s.id AND l2.user_id = ?) as liked
                FROM stories s
                JOIN users u ON s.author_id = u.id
                LEFT JOIN likes l ON s.id = l.story_id
                LEFT JOIN comments c ON s.id = c.story_id
                GROUP BY s.id
                ORDER BY s.timestamp DESC
            ''', (session['user_id'],))
            stories = [{'id': row['id'], 'title': row['title'], 'content': row['content'], 'author': row['author'], 
                        'likes': row['likes'], 'comment_count': row['comment_count'], 'liked': bool(row['liked'])} for row in c.fetchall()]
        
        logger.debug(f"Dashboard data prepared: role={role}, stories={len(stories)}")
        return jsonify({'success': True, 'role': role, 'stories': stories})
    except sqlite3.Error as e:
        logger.error(f"Database error in dashboard: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    except Exception as e:
        logger.error(f"Unexpected error in dashboard: {e}")
        return jsonify({'success': False, 'message': 'Server error'}), 500
    finally:
        conn.close()

@app.route('/delete/<int:story_id>', methods=['POST'])
def delete_story(story_id):
    logger.debug(f"Delete story request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('DELETE FROM stories WHERE id = ? AND author_id = ?', 
                 (story_id, session['user_id']))
        if c.rowcount > 0:
            conn.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Unauthorized or story not found'}), 404
    except sqlite3.Error as e:
        logger.error(f"Database error in delete_story: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/like/<int:story_id>', methods=['POST'])
def like_story(story_id):
    logger.debug(f"Like story request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('SELECT id FROM likes WHERE story_id = ? AND user_id = ?', 
                 (story_id, session['user_id']))
        if c.fetchone():
            c.execute('DELETE FROM likes WHERE story_id = ? AND user_id = ?', 
                     (story_id, session['user_id']))
        else:
            c.execute('INSERT INTO likes (story_id, user_id, timestamp) VALUES (?, ?, ?)',
                     (story_id, session['user_id'], datetime.now()))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        logger.error(f"Database error in like_story: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/comment/<int:story_id>', methods=['POST'])
def post_comment(story_id):
    logger.debug(f"Post comment request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    data = request.get_json()
    if not data.get('content', '').strip():
        return jsonify({'success': False, 'message': 'Comment cannot be empty'}), 400
    
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('INSERT INTO comments (story_id, user_id, content, timestamp) VALUES (?, ?, ?, ?)',
                 (story_id, session['user_id'], data['content'], datetime.now()))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        logger.error(f"Database error in post_comment: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/comments/<int:story_id>')
def get_comments(story_id):
    logger.debug(f"Get comments request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT c.content, u.username as author
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.story_id = ?
            ORDER BY c.timestamp DESC
        ''', (story_id,))
        comments = [{'content': row['content'], 'author': row['author']} for row in c.fetchall()]
        return jsonify(comments)
    except sqlite3.Error as e:
        logger.error(f"Database error in get_comments: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/likes/<int:story_id>')
def get_likes(story_id):
    logger.debug(f"Get likes request for story_id {story_id} with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT u.username
            FROM likes l
            JOIN users u ON l.user_id = u.id
            WHERE l.story_id = ?
            ORDER BY l.timestamp DESC
        ''', (story_id,))
        likes = [{'username': row['username']} for row in c.fetchall()]
        logger.debug(f"Fetched {len(likes)} likes for story_id {story_id}")
        return jsonify(likes)
    except sqlite3.Error as e:
        logger.error(f"Database error in get_likes: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

@app.route('/search')
def search():
    logger.debug(f"Search request with session: {session}")
    logger.debug(f"Request cookies: {request.cookies}")
    query = request.args.get('q', '')
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute('''
            SELECT s.id, s.title, s.content, u.username as author, 
                   COUNT(l.id) as likes, COUNT(c.id) as comment_count,
                   EXISTS(SELECT 1 FROM likes l2 WHERE l2.story_id = s.id AND l2.user_id = ?) as liked
            FROM stories s
            JOIN users u ON s.author_id = u.id
            LEFT JOIN likes l ON s.id = l.story_id
            LEFT JOIN comments c ON s.id = c.story_id
            WHERE s.title LIKE ? OR s.content LIKE ?
            GROUP BY s.id
            ORDER BY s.timestamp DESC
        ''', (session.get('user_id', 0), f'%{query}%', f'%{query}%'))
        stories = [{'id': row['id'], 'title': row['title'], 'content': row['content'], 'author': row['author'], 
                    'likes': row['likes'], 'comment_count': row['comment_count'], 'liked': bool(row['liked'])} for row in c.fetchall()]
        return jsonify(stories)
    except sqlite3.Error as e:
        logger.error(f"Database error in search: {e}")
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)