from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# User model
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    phone = db.Column(db.String)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_picture = db.Column(db.String(255), default='default.jpg')
    bio = db.Column(db.Text, nullable=True)
    socials = db.Column(db.String)
    no_of_ideas = db.Column(db.Integer, default=0)  # Count of no_of_ideas
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    messages_sent = db.relationship('Message', backref='sender', lazy=True, foreign_keys='Message.sender_id', cascade='all, delete-orphan')
    messages_received = db.relationship('Message', backref='receiver', lazy=True, foreign_keys='Message.receiver_id', cascade='all, delete-orphan')
    ideas = db.relationship('Idea', backref='author', lazy=True, cascade='all, delete-orphan')
    stories = db.relationship('Story', backref='author', lazy=True, cascade='all, delete-orphan')
    saved_ideas = db.relationship('SavedIdea', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    community_requests = db.relationship('CommunityRequest', backref='user', lazy=True)
    idea_reviews = db.relationship('IdeaReview', backref='reviewer', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            'full_name': f"{self.first_name} {self.last_name}",
            "phone": self.phone,
            "username": self.username,
            'socials': self.socials.split(',') if self.socials else [],  # Convert socials to list of URLs
            "email": self.email,
            "profile_picture": self.profile_picture,
            "bio": self.bio,
            "no_of_ideas": self.no_of_ideas,
            "created_at": self.created_at.isoformat()
        }

# Idea model
class Idea(db.Model):
    __tablename__ = 'ideas'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(50), nullable=True)
    content = db.Column(db.Text, nullable=False)
    tier = db.Column(db.Text, nullable=True)
    images_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approvals_count = db.Column(db.Integer, default=0)  # Count of approvals

    reviews = db.relationship('IdeaReview', backref='idea', lazy=True)

    @property
    def rate_aggregate(self):
        """
        Calculate the average rating of the agent based on the associated reviews.
        Returns 0 if there are no reviews.
        """
        if not self.reviews:
            return 0  # No reviews, average rating is 0
        total_rating = sum(review.rating for review in self.reviews)
        return round(total_rating / len(self.reviews))  # Rounded to the nearest whole number

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "content": self.content,
            "tier": self.tier,
            "images_url": self.images_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "approvals_count": self.approvals_count,
            'rate_average': self.rate_aggregate,
            "author": self.author.to_dict() if self.author else None
        }

# IdeaReview model
class IdeaReview(db.Model):
    __tablename__ = 'idea_reviews'

    id = db.Column(db.Integer, primary_key=True)
    idea_id = db.Column(db.Integer, db.ForeignKey('ideas.id'), nullable=False)  # Reviewed idea
    reviewer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Reviewer
    comment = db.Column(db.Text, nullable=True)  # Review comment
    rating = db.Column(db.Integer, nullable=False)  # Rating (e.g., 1-5)
    approving = db.Column(db.Boolean, default=False)  # Whether reviewer is approving
    reviewed_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp of review

    def to_dict(self):
        return {
            "id": self.id,
            "idea_id": self.idea_id,
            "reviewer_id": self.reviewer_id,
            "comment": self.comment,
            "rating": self.rating,
            "approving": self.approving,
            "reviewed_at": self.reviewed_at.isoformat(),
        }        

# Story model
class Story(db.Model):
    __tablename__ = 'stories'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    images_url = db.Column(db.String(255), nullable=False)
    caption = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "images_url": self.images_url,
            "caption": self.caption,
            "created_at": self.created_at.isoformat(),
            "author": self.author.to_dict() if self.author else None
        }

# Message model
class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "is_read": self.is_read,
            "sender": self.sender.to_dict() if self.sender else None,
            "receiver": self.receiver.to_dict() if self.receiver else None
        }

# Saved Idea model
class SavedIdea(db.Model):
    __tablename__ = 'saved_ideas'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # The user who saved the idea
    idea_id = db.Column(db.Integer, db.ForeignKey('ideas.id'), nullable=False)  # The idea that is saved
    saved_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for when it was saved

    idea = db.relationship('Idea', backref='saved_by', lazy=True)  # Access the idea being saved

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "idea_id": self.idea_id,
            "saved_at": self.saved_at.isoformat()
        }

# Notification model
class Notification(db.Model):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "is_read": self.is_read,
            "user": self.user.to_dict() if self.user else None
        }

# Community Request model
class CommunityRequest(db.Model):
    __tablename__ = 'community_requests'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="Pending")  # Status: Pending, Approved, Rejected

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "user": self.user.to_dict() if self.user else None
        }

# Theme Settings model
class ThemeSetting(db.Model):
    __tablename__ = 'theme_settings'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    theme = db.Column(db.String(20), default="Light")  # Light or Dark

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "theme": self.theme
        }

class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)        