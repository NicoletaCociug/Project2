from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

# Association table for the many-to-many relationship between users and groups
user_group = db.Table('user_group',
    db.Column('username', db.String, db.ForeignKey('user.username'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.group_id'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'user'
    username = db.Column(db.String, primary_key=True)
    password = db.Column(db.String(256)) #for internal use only
    public_key = db.Column(db.Text)

    def set_password(self, password):
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password, password)

    # Relationships
    groups = db.relationship('Group', secondary=user_group, backref=db.backref('users', lazy=True))


class Group(db.Model):
    __tablename__ = 'group'
    group_id = db.Column(db.Integer, primary_key=True)
    group_name = db.Column(db.String, unique=True, nullable=False)
    #relationship
    #users = db.relationship('User', secondary=user_group, lazy='subquery', back_populates='groups_belongs_to')
    #group_users = db.relationship('User', secondary=user_group, lazy='subquery', 
    #back_populates='groups_belongs_to')

class GroupUserLink(db.Model):
    __tablename__ = 'group_user_link'
    username = db.Column(db.String, db.ForeignKey('user.username'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), primary_key=True)
    encrypted_key = db.Column(db.String)  # Store the encrypted symmetric key here

    user = db.relationship('User', backref='group_links')
    group = db.relationship('Group', backref='user_links')


class Message(db.Model):
    __tablename__ = 'message'
    message_id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.group_id'), nullable=False)
    sender_username = db.Column(db.String, db.ForeignKey('user.username'), nullable=False)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())

#User.group_links = db.relationship('GroupUserLink', back_populates='user')
#Group.user_links = db.relationship('GroupUserLink', back_populates='group')
