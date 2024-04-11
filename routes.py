from base64 import b64decode, b64encode
from flask import request, jsonify
from models import db, User, Group, GroupUserLink, Message
import crypto_utils


def setup_routes(app):
    @app.route('/')
    def index():
        return "Application is running"
        
    @app.route('/register', methods=['POST'])
    def register_user():
        data = request.get_json()
        if not data:
            return jsonify({"message": "No data provided"}), 400

        username = data.get('username')
        password = data.get('password')
        public_key = data.get('public_key')
        
        if not all([username, password, public_key]):
            missing = [field for field in ['username', 'password', 'public_key'] if not data.get(field)]
            return jsonify({"message": f"Missing fields: {', '.join(missing)}"}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"message": "Username already exists"}), 409
        
        try:
            new_user = User(username=username, public_key=public_key)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User registered successfully!'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'Error registering user: {str(e)}'}), 500
    
    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            return jsonify({'message': 'Login successful!'}), 200
        return jsonify({'message': 'Invalid username or password'}), 401

   
    @app.route('/users', methods=['GET'])
    def get_users():
        users = User.query.all()  # Fetch all users from the database
        users_list = [{'username': user.username} for user in users]  # Create a list of dictionaries with usernames
        return jsonify(users_list), 200

    @app.route('/groups', methods=['GET'])
    def get_groups():
        groups = Group.query.all()
        groups_list = [group.group_name for group in groups]  # Return just the name
        return jsonify(groups_list), 200


    @app.route('/user_groups/<username>', methods=['GET'])
    def get_user_groups(username):
        user = User.query.filter_by(username=username).first()
        if user:
            user_groups = [group.group_name for group in user.groups]
            print(f"the user groups : {user_groups}")
            return jsonify({'your_groups': user_groups}), 200
        else:
            return jsonify({'message': 'User not found'}), 404



    @app.route('/create_group', methods=['POST'])
    def create_group():
        data = request.get_json()
        group_name = data.get('group_name')
        members = data.get('members')  # List of usernames to be added to the group

        # Create new Group instance
        new_group = Group(group_name=group_name)
        db.session.add(new_group)
        db.session.flush()

        #generate the symmetric key for the new group
        symmetric_key = crypto_utils.generate_symmetric_key_for_group()

        #encrypt this key with eack member's public key and add users to the group
        for username in members:
            user = User.query.filter_by(username=username).first()
            if user:
                new_group.users.append(user) #append user to the group
                #encrypt the symmetric key with the user's public key
                encrypted_symmetric_key = crypto_utils.encrypt_symmetric_key(symmetric_key, user.public_key)
                #create and add the GroupUserLink entry
                link = GroupUserLink(username=username, group_id=new_group.group_id, encrypted_key=encrypted_symmetric_key)
                db.session.add(link)
            else:
                db.session.rollback()
                # Handle the case where the user does not exist
                return jsonify({'message': f'User {username} not found'}), 404

        # Add to the session and commit
        db.session.commit()
        return jsonify({'message': 'Group created successfully!'}), 201

    @app.route('/send_message', methods=['POST'])
    def send_message():
        data = request.get_json()
        group_name = data.get('group_name')
        sender_username = data.get('sender_username')
        ciphertext = data.get('ciphertext')

        # Decode the base64-encoded ciphertext to bytes
        try:
            ciphertext_bytes = b64decode(ciphertext)
        except Exception as e:
            return jsonify({'message': f'Invalid ciphertext encoding: {str(e)}'}), 400

        # Find the group by name
        group = Group.query.filter_by(group_name=group_name).first()
        if group is None:
            return jsonify({'message': 'Group not found'}), 404

        # Find the sender by username
        sender = User.query.filter_by(username=sender_username).first()
        if sender is None:
            return jsonify({'message': 'Sender not found'}), 404

        # Check if the sender is part of the group
        if sender not in group.users:
            return jsonify({'message': 'You are not a member of this group'}), 403

        # Create a new Message instance with the binary ciphertext
        new_message = Message(group_id=group.group_id, sender_username=sender_username, ciphertext=ciphertext_bytes)

        # Add to the session and commit
        db.session.add(new_message)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': f'Failed to send message: {str(e)}'}), 500

        return jsonify({'message': 'Message sent successfully!'}), 201

    @app.route('/fetch_messages_by_name/<group_name>', methods=['GET'])
    def fetch_messages_by_name(group_name):
        group = Group.query.filter_by(group_name=group_name).first()
        if not group:
            return jsonify({'message': 'Group not found'}), 404

        messages = Message.query.filter_by(group_id=group.group_id).all()
        messages_data = []
        for message in messages:
            # Convert ciphertext bytes to base64 encoded string
            encoded_ciphertext = b64encode(message.ciphertext).decode('utf-8')
            messages_data.append({
                'message_id': message.message_id,
                'sender_username': message.sender_username,
                'ciphertext': encoded_ciphertext,
            })

        return jsonify({'messages': messages_data}), 200
        
    @app.route('/fetch_messages/<int:group_id>', methods=['GET'])
    def fetch_messages(group_id):
        messages = Message.query.filter_by(group_id=group_id).all()
        messages_data = [{'message_id': message.message_id, 'sender_username': message.sender_username, 'ciphertext': message.ciphertext} for message in messages]
        
        return jsonify({'messages': messages_data}), 200
    
    @app.route('/non_group_users/<group_name>', methods=['GET'])
    def non_group_users(group_name):
        # Return a list of users not in the specified group
        group = Group.query.filter_by(group_name=group_name).first()
        if group:
            group_members = [user.username for user in group.users]
            non_members = User.query.filter(User.username.notin_(group_members)).all()
            return jsonify([user.username for user in non_members]), 200
        else:
            return jsonify({"message": "Group not found"}), 404

    @app.route('/add_user_to_group', methods=['POST'])
    def add_user_to_group():
        # Add a user to an existing group
        data = request.get_json()
        group_name = data.get('group_name')
        username_to_add = data.get('username')
        
        group = Group.query.filter_by(group_name=group_name).first()
        user = User.query.filter_by(username=username_to_add).first()
        
        if group and user:
            group.users.append(user)
            db.session.commit()
            return jsonify({'message': f'User {username_to_add} added to group {group_name}'}), 200
        else:
            return jsonify({'message': 'Group or user not found'}), 404

    @app.route('/get_encrypted_symmetric_key/<group_name>/<username>', methods=['GET'])
    def get_encrypted_symmetric_key(group_name, username):
        group = Group.query.filter_by(group_name=group_name).first()
        if not group:
            return jsonify({'message': 'Group not found'}), 404

        #ensure the user is part of the group
        if username not in [user.username for user in group.users]:
            return jsonify({'message': 'Access denied'}), 403

        link = GroupUserLink.query.filter_by(username=username, group_id=group.group_id).first()
        if not link:
            return jsonify({'message': 'No key found or not a member'}), 404
        
        return jsonify({'encrypted_symmetric_key': link.encrypted_key}), 200


