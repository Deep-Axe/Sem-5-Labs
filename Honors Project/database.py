import json
import os

DATA_DIR = 'data'
BOOKS_FILE = os.path.join(DATA_DIR, 'books.json')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
REVIEWS_FILE = os.path.join(DATA_DIR, 'reviews.json')

def init_db():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    
    if not os.path.exists(BOOKS_FILE):
        # Initial dummy data
        books = [
            # Technology & Computer Science
            {"id": 1, "title": "The Joy of Python", "author": "Guido van Rossum", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 2, "title": "Flask Web Development", "author": "Miguel Grinberg", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 3, "title": "Clean Code", "author": "Robert C. Martin", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 4, "title": "The Pragmatic Programmer", "author": "Andrew Hunt", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 5, "title": "Introduction to Algorithms", "author": "Thomas H. Cormen", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 6, "title": "Design Patterns", "author": "Erich Gamma", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 7, "title": "You Don't Know JS", "author": "Kyle Simpson", "genre": "Technology", "status": "Available", "issued_to": None},
            {"id": 8, "title": "Cracking the Coding Interview", "author": "Gayle Laakmann McDowell", "genre": "Technology", "status": "Available", "issued_to": None},
            
            # Data Science & AI
            {"id": 9, "title": "Data Science from Scratch", "author": "Joel Grus", "genre": "Data Science", "status": "Available", "issued_to": None},
            {"id": 10, "title": "Deep Learning", "author": "Ian Goodfellow", "genre": "Data Science", "status": "Available", "issued_to": None},
            {"id": 11, "title": "Hands-On Machine Learning", "author": "Aurélien Géron", "genre": "Data Science", "status": "Available", "issued_to": None},
            {"id": 12, "title": "Pattern Recognition and Machine Learning", "author": "Christopher Bishop", "genre": "Data Science", "status": "Available", "issued_to": None},
            {"id": 13, "title": "Python for Data Analysis", "author": "Wes McKinney", "genre": "Data Science", "status": "Available", "issued_to": None},

            # Fiction & Classics
            {"id": 14, "title": "Harry Potter and the Sorcerer's Stone", "author": "J.K. Rowling", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 15, "title": "To Kill a Mockingbird", "author": "Harper Lee", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 16, "title": "1984", "author": "George Orwell", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 17, "title": "The Great Gatsby", "author": "F. Scott Fitzgerald", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 18, "title": "Pride and Prejudice", "author": "Jane Austen", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 19, "title": "The Catcher in the Rye", "author": "J.D. Salinger", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 20, "title": "Brave New World", "author": "Aldous Huxley", "genre": "Fiction", "status": "Available", "issued_to": None},
            {"id": 21, "title": "The Alchemist", "author": "Paulo Coelho", "genre": "Fiction", "status": "Available", "issued_to": None},

            # Mystery & Thriller
            {"id": 22, "title": "The Adventures of Sherlock Holmes", "author": "Arthur Conan Doyle", "genre": "Mystery", "status": "Available", "issued_to": None},
            {"id": 23, "title": "Gone Girl", "author": "Gillian Flynn", "genre": "Mystery", "status": "Available", "issued_to": None},
            {"id": 24, "title": "The Girl with the Dragon Tattoo", "author": "Stieg Larsson", "genre": "Mystery", "status": "Available", "issued_to": None},
            {"id": 25, "title": "The Da Vinci Code", "author": "Dan Brown", "genre": "Mystery", "status": "Available", "issued_to": None},
            {"id": 26, "title": "And Then There Were None", "author": "Agatha Christie", "genre": "Mystery", "status": "Available", "issued_to": None},

            # Fantasy & Sci-Fi
            {"id": 27, "title": "The Hobbit", "author": "J.R.R. Tolkien", "genre": "Fantasy", "status": "Available", "issued_to": None},
            {"id": 28, "title": "Dune", "author": "Frank Herbert", "genre": "Sci-Fi", "status": "Available", "issued_to": None},
            {"id": 29, "title": "The Name of the Wind", "author": "Patrick Rothfuss", "genre": "Fantasy", "status": "Available", "issued_to": None},
            {"id": 30, "title": "Ender's Game", "author": "Orson Scott Card", "genre": "Sci-Fi", "status": "Available", "issued_to": None},
            {"id": 31, "title": "A Game of Thrones", "author": "George R.R. Martin", "genre": "Fantasy", "status": "Available", "issued_to": None},

            # History & Biography
            {"id": 32, "title": "Sapiens: A Brief History of Humankind", "author": "Yuval Noah Harari", "genre": "History", "status": "Available", "issued_to": None},
            {"id": 33, "title": "Educated", "author": "Tara Westover", "genre": "Biography", "status": "Available", "issued_to": None},
            {"id": 34, "title": "Becoming", "author": "Michelle Obama", "genre": "Biography", "status": "Available", "issued_to": None},
            {"id": 35, "title": "Steve Jobs", "author": "Walter Isaacson", "genre": "Biography", "status": "Available", "issued_to": None},
            {"id": 36, "title": "Guns, Germs, and Steel", "author": "Jared Diamond", "genre": "History", "status": "Available", "issued_to": None},
            {"id": 37, "title": "The Diary of a Young Girl", "author": "Anne Frank", "genre": "Biography", "status": "Available", "issued_to": None},

            # Science & Philosophy
            {"id": 38, "title": "Cosmos", "author": "Carl Sagan", "genre": "Science", "status": "Available", "issued_to": None},
            {"id": 39, "title": "A Brief History of Time", "author": "Stephen Hawking", "genre": "Science", "status": "Available", "issued_to": None},
            {"id": 40, "title": "Thinking, Fast and Slow", "author": "Daniel Kahneman", "genre": "Psychology", "status": "Available", "issued_to": None},
            {"id": 41, "title": "Meditations", "author": "Marcus Aurelius", "genre": "Philosophy", "status": "Available", "issued_to": None},
            {"id": 42, "title": "The Selfish Gene", "author": "Richard Dawkins", "genre": "Science", "status": "Available", "issued_to": None},
            {"id": 43, "title": "Beyond Good and Evil", "author": "Friedrich Nietzsche", "genre": "Philosophy", "status": "Available", "issued_to": None},

            # Business & Self-Help
            {"id": 44, "title": "Atomic Habits", "author": "James Clear", "genre": "Self-Help", "status": "Available", "issued_to": None},
            {"id": 45, "title": "Rich Dad Poor Dad", "author": "Robert Kiyosaki", "genre": "Business", "status": "Available", "issued_to": None},
            {"id": 46, "title": "Zero to One", "author": "Peter Thiel", "genre": "Business", "status": "Available", "issued_to": None},
            {"id": 47, "title": "The Power of Habit", "author": "Charles Duhigg", "genre": "Self-Help", "status": "Available", "issued_to": None},
            {"id": 48, "title": "How to Win Friends and Influence People", "author": "Dale Carnegie", "genre": "Self-Help", "status": "Available", "issued_to": None},
            {"id": 49, "title": "Deep Work", "author": "Cal Newport", "genre": "Self-Help", "status": "Available", "issued_to": None},
            {"id": 50, "title": "Shoe Dog", "author": "Phil Knight", "genre": "Business", "status": "Available", "issued_to": None}
        ]
        save_data(BOOKS_FILE, books)

    if not os.path.exists(USERS_FILE):
        # Default admin user (password: admin123) - In real app, hash this!
        # We will handle hashing in the auth logic, but for initial seed we might need a pre-hashed value or handle it on first run.
        # For simplicity here, we'll start empty and let the user register, or add a default admin.
        users = []
        save_data(USERS_FILE, users)

    if not os.path.exists(REVIEWS_FILE):
        save_data(REVIEWS_FILE, [])

def load_data(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def save_data(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def get_books():
    return load_data(BOOKS_FILE)

def save_books(books):
    save_data(BOOKS_FILE, books)

def get_users():
    return load_data(USERS_FILE)

def save_users(users):
    save_data(USERS_FILE, users)

def get_reviews():
    return load_data(REVIEWS_FILE)

def save_reviews(reviews):
    save_data(REVIEWS_FILE, reviews)
