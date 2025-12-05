from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import database
import utils
import random
import os
import re

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_libportal' # Change this in production

# Initialize DB
database.init_db()

# --- Helpers ---
def get_current_user():
    if 'user_id' in session:
        users = database.get_users()
        for user in users:
            if user['id'] == session['user_id']:
                return user
    return None

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def admin_required(f):
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'admin':
            flash("Access denied: Admins only.")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'student') # Default to student
        
        # Password Validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long.')
            return redirect(url_for('register'))
        if not re.search(r"[A-Z]", password):
            flash('Password must contain at least one uppercase letter.')
            return redirect(url_for('register'))
        if not re.search(r"[a-z]", password):
            flash('Password must contain at least one lowercase letter.')
            return redirect(url_for('register'))
        if not re.search(r"[0-9]", password):
            flash('Password must contain at least one digit.')
            return redirect(url_for('register'))
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash('Password must contain at least one special character.')
            return redirect(url_for('register'))

        users = database.get_users()
        if any(u['username'] == username for u in users):
            flash('Username already exists')
            return redirect(url_for('register'))
        
        new_user = {
            "id": len(users) + 1,
            "username": username,
            "password": generate_password_hash(password),
            "role": role,
            "history": [] # List of book IDs returned
        }
        users.append(new_user)
        database.save_users(users)
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = database.get_users()
        user = next((u for u in users if u['username'] == username), None)
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    books = database.get_books()
    
    # Stats
    total_books = len(books)
    issued_books = len([b for b in books if b['status'] == 'Issued'])
    available_books = total_books - issued_books
    
    # Recommendations
    recommendations = utils.get_recommendations(user['history'], books)
    
    # My Issued Books
    my_books = [b for b in books if b['issued_to'] == user['id']]
    
    return render_template('dashboard.html', user=user, 
                           total=total_books, issued=issued_books, available=available_books,
                           recommendations=recommendations, my_books=my_books)

@app.route('/books')
@login_required
def books():
    search_query = request.args.get('q', '').lower()
    all_books = database.get_books()
    reviews = database.get_reviews()
    
    # Calculate sentiment for each book
    book_sentiments = {}
    for book in all_books:
        book_reviews = [r['sentiment'] for r in reviews if r['book_id'] == book['id']]
        if book_reviews:
            # Simple logic: Majority wins, or "Mixed"
            pos = book_reviews.count('Positive')
            neg = book_reviews.count('Negative')
            neu = book_reviews.count('Neutral')
            
            if pos > neg and pos > neu:
                sentiment = "Positive"
            elif neg > pos and neg > neu:
                sentiment = "Negative"
            elif neu > pos and neu > neg:
                sentiment = "Neutral"
            else:
                sentiment = "Mixed"
            book_sentiments[book['id']] = sentiment
        else:
            book_sentiments[book['id']] = "No Reviews"

    if search_query:
        filtered_books = [b for b in all_books if search_query in b['title'].lower() or search_query in b['author'].lower()]
    else:
        filtered_books = all_books
        
    return render_template('books.html', books=filtered_books, user=get_current_user(), sentiments=book_sentiments)

@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    reviews = database.get_reviews()
    books = database.get_books()
    users = database.get_users()
    
    # Enrich reviews with book and user names
    enriched_reviews = []
    for review in reviews:
        book = next((b for b in books if b['id'] == review['book_id']), None)
        user = next((u for u in users if u['id'] == review['user_id']), None)
        if book and user:
            enriched_reviews.append({
                "book_title": book['title'],
                "username": user['username'],
                "content": review['content'],
                "sentiment": review['sentiment']
            })
            
    return render_template('admin_feedback.html', reviews=enriched_reviews)

@app.route('/add_book', methods=['POST'])
@admin_required
def add_book():
    title = request.form['title']
    author = request.form['author']
    genre = request.form['genre']
    
    books = database.get_books()
    new_book = {
        "id": len(books) + 1,
        "title": title,
        "author": author,
        "genre": genre,
        "status": "Available",
        "issued_to": None
    }
    books.append(new_book)
    database.save_books(books)
    flash('Book added successfully!')
    return redirect(url_for('books'))

@app.route('/issue/<int:book_id>')
@login_required
def issue_book(book_id):
    books = database.get_books()
    user = get_current_user()
    
    for book in books:
        if book['id'] == book_id:
            if book['status'] == 'Available':
                book['status'] = 'Issued'
                book['issued_to'] = user['id']
                database.save_books(books)
                flash(f'You have issued {book["title"]}')
            else:
                flash('Book is not available')
            break
    return redirect(url_for('books'))

@app.route('/return/<int:book_id>')
@login_required
def return_book(book_id):
    books = database.get_books()
    users = database.get_users()
    user = get_current_user()
    
    for book in books:
        if book['id'] == book_id and book['issued_to'] == user['id']:
            book['status'] = 'Available'
            book['issued_to'] = None
            
            # Update user history for recommendations
            # We need to find the user object in the list to update it
            for u in users:
                if u['id'] == user['id']:
                    if book_id not in u['history']:
                        u['history'].append(book_id)
                    break
            
            database.save_books(books)
            database.save_users(users)
            flash(f'You have returned {book["title"]}')
            break
    return redirect(url_for('dashboard'))

@app.route('/review/<int:book_id>', methods=['POST'])
@login_required
def add_review(book_id):
    content = request.form['content']
    sentiment = utils.analyze_sentiment(content)
    
    reviews = database.get_reviews()
    reviews.append({
        "book_id": book_id,
        "user_id": session['user_id'],
        "content": content,
        "sentiment": sentiment
    })
    database.save_reviews(reviews)
    flash(f'Review added! Sentiment analysis says: {sentiment}')
    return redirect(url_for('books'))

if __name__ == '__main__':
    app.run(debug=True)
