from flask import Flask
from models import db
from routes import setup_routes  # Assuming this is where you define your app routes.

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Kof62708.@localhost/new_database'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# If db is initialized in models.py as db = SQLAlchemy(), you should only call init_app here.
db.init_app(app)

with app.app_context():
    db.create_all()  # This will create the database tables for all your models if they don't exist.

setup_routes(app)  # Setup the Flask routes as defined in your routes module.

if __name__ == '__main__':
    app.run(debug=True)
