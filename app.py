from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import date

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.app_context().push()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    blog_id = db.Column(db.Integer, db.ForeignKey('blog.id'), nullable=False)
    author_id = db.Column(db.Text, db.ForeignKey('user.id'), nullable=False)
    author_name = db.Column(db.String(100), nullable=True)
    comment_date = db.Column(db.String(100), nullable=True)

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)

class RolePermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permission.id'), nullable=False)

class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def has_permission(user, permission):
    if user.role == 'admin':
        return True
    elif user.role == 'user':
        role_id = Role.query.filter_by(name='user').first().id
        role_permissions = RolePermission.query.filter_by(role_id=role_id).all()
        permissions = [Permission.query.get(rp.permission_id).name for rp in role_permissions]
        # user_permissions = [p.name for p in user.roles[0].permissions]
        return permission in permissions
    return False

def fetch_user(user):
    try:
        role = user.role
        public_user = user
    except AttributeError: # role not assigned
        class public_user():
            role = ''
    return public_user

@app.route('/')
def index():
    blogs = Blog.query.all()
    user = fetch_user(current_user)
    return render_template('index.html', blogs=blogs, user = user)

@app.route('/dashboard')
def dashboard():
    try:
        if current_user.role == 'admin':
            blogs = Blog.query.all()
            return render_template('dashboard.html', blogs=blogs)
        else:
            return render_template('no_permission.html')
    except AttributeError:
        return render_template('no_permission.html')

@app.route('/blog/<int:blog_id>')
def blog(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    comments = Comment.query.filter(Comment.blog_id == blog_id).all()
    user = fetch_user(current_user)
    number_comm = len(comments)
    return render_template('blog.html', blog=blog, comments = comments, num_comm = number_comm, user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username is already taken. Please choose a different one.", 400

        # Create a new user with the 'user' role
        new_user = User(username=username, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()

        # Log in the new user automatically
        login_user(new_user)
        return redirect(url_for('index'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if has_permission(current_user, 'create'):
        if request.method == 'POST':
            title = request.form['title']
            type = request.form['category']
            description = request.form['description']
            content = request.form['content']
            date_blog = date.today()
            blog = Blog(title=title, content=content, type=type, description=description, date=date_blog, author_id=current_user.id)
            db.session.add(blog)
            db.session.commit()
            return redirect(url_for('index'))
        return render_template('create.html')
    else:
        return "Permission Denied", 403

@app.route('/comment/<int:blog_id>', methods=['POST'])
@login_required
def comment(blog_id):
    if request.method == "POST":
        comment_date = date.today()
        content = request.form['content']
        comment = Comment(content = content, comment_date = comment_date, author_id = current_user.id, blog_id = blog_id, author_name = current_user.username)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('blog', blog_id = blog_id))
    return render_template(url_for('blog', blog_id=blog_id))

@app.route('/update/<int:blog_id>', methods=['GET', 'POST'])
@login_required
def update(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    if has_permission(current_user, 'update') and current_user.id == blog.author_id:
        if request.method == 'POST':
            blog.title = request.form['title']
            blog.type = request.form['category']
            blog.description = request.form['description']
            blog.content = request.form['content']
            db.session.commit()
            return redirect(url_for('index'))
        return render_template('update.html', blog=blog)
    else:
        return "Permission Denied", 403

@app.route('/delete/<int:blog_id>')
@login_required
def delete(blog_id):
    blog = Blog.query.get_or_404(blog_id)
    if has_permission(current_user, 'delete') and current_user.id == blog.author_id:
        db.session.delete(blog)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        return "Permission Denied", 403

if __name__ == '__main__':
    app.run(debug=True)
