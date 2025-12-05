import random
from textblob import TextBlob

def analyze_sentiment(text):
    blob = TextBlob(text)
    polarity = blob.sentiment.polarity
    if polarity > 0.1:
        return "Positive"
    elif polarity < -0.1:
        return "Negative"
    else:
        return "Neutral"

# --- Recommendation System (Course Topic: Six Degrees/Similarities) ---
def get_recommendations(user_history, all_books):
    # Simple recommendation: Recommend books from genres the user has read
    if not user_history:
        # Random recommendation if no history
        return random.sample(all_books, min(3, len(all_books)))
    
    read_genres = set()
    for book_id in user_history:
        # Find book genre (inefficient but simple for small lists)
        for b in all_books:
            if b['id'] == book_id:
                read_genres.add(b['genre'])
                break
    
    recommendations = []
    for book in all_books:
        if book['genre'] in read_genres and book['id'] not in user_history:
            recommendations.append(book)
            
    if not recommendations:
        # Fallback to random
        return random.sample(all_books, min(3, len(all_books)))
        
    return recommendations[:3]
