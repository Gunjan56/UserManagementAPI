from functools import wraps
import os
import re
from flask_mail import Message, Mail
import base64 
from flask import request, jsonify, abort, send_from_directory
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from models.model import db, User, Post, Message, Like, Comment, Follow
from utils import create_app
app, socketio = create_app()
mail = Mail(app)
email_validation = r'^[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+$'

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def secure_password(password):
    return generate_password_hash(password)    

def roles_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            if user.role not in roles:
                abort(403, 'Insufficient permissions')
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            data['profile_picture'] = filename

    if not re.match(email_validation, data.get('email')):
        return jsonify({'message': 'Enter a valid email'}), 400

    if not data.get('username') or not data.get('email') or not data.get('password'):
        abort(400, 'missing required details')

    user = User.query.filter_by(username=data.get('username'), email=data.get('email')).first()

    if user:
        return jsonify({'message': "User already registered"}), 400

    hashed_password = generate_password_hash(data.get('password'))

    new_user = User(
        username=data.get('username'),
        email=data.get('email'),
        password=hashed_password,
        profile_picture=data.get('profile_picture')
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json

    if not data.get('username') or not data.get('password'):
        abort(400, 'Missing required details')

    user = User.query.filter_by(username=data.get('username')).first()

    if not user or not check_password_hash(user.password, data['password']):
        abort(401, 'Invalid username or password')

    access_token = create_access_token(identity=user.id)

    return jsonify(access_token=access_token), 200

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        reset_token = base64.b64encode(email.encode('utf-8')).decode('utf-8')

        send_reset_password_email(email, reset_token)

        return jsonify({'message': 'Reset password link sent to your email'})
    else:
        return jsonify({'message': 'User not found'}), 404

def send_reset_password_email(user_email, reset_token):
    msg = Message('Reset Your Password', sender=os.getenv('MAIL_USERNAME'), recipients=[user_email])
    msg.body = f'Reset your password: {reset_token}'
    mail.send(msg)


@app.route('/reset_password/<token>', methods=['POST'])
def reset_password(token):
   
    data = request.get_json()
    new_password = data['new_password']
    confirm_password = data['confirm_password']
    
    if new_password != confirm_password:
        return jsonify({'message': 'New password and confirm password do not match'}), 400

    email = base64.b64decode(token).decode('utf-8')
    
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = generate_password_hash(new_password)
        db.session.commit()
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404


@app.route('/profile/picture', methods=['PUT'])
@jwt_required()
def update_profile_picture():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        abort(404, 'user not found')

    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(profile_picture.filename)
            profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.profile_picture = filename
            db.session.commit()

            return jsonify({'message': 'Profile picture updated successfully'}), 200

    return jsonify({'error': 'No profile picture'}), 400

@app.route('/profile', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def manage_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        abort(404, 'user not found')

    if request.method == 'GET':
        followers = [follower.username for follower in user.follower]
        following = [following.username for following in user.following]

        return jsonify({
            'username': user.username,
            'email': user.email,
            'profile_picture': user.profile_picture,
            'followers': followers,
            'following': following
        }), 200

    elif request.method == 'PUT':
        data = request.json

        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)

        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture and allowed_file(profile_picture.filename):
                filename = secure_filename(profile_picture.filename)
                profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_picture = filename

        db.session.commit()

        return jsonify({'message': 'Profile updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'User deleted successfully'}), 200

@app.route('/user/<int:user_id>', methods=['GET'])
@jwt_required()
def view_profile(user_id):
    user = User.query.get(user_id)

    if not user:
        abort(404, 'user not found')

    followers = [follower.follower_id for follower in user.follower]
    following = [following.followed_id for following in user.following]

    return jsonify({
        'username': user.username,
        'email': user.email,
        'profile_picture': user.profile_picture,
        'followers': followers,
        'following': following
    }), 200

@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        abort(404, 'user not found')

    data = request.json

    content = data.get('content')

    if not content:
        abort(400, 'Content is required')

    new_post = Post(
        content=content,
        user_id=current_user_id
    )

    db.session.add(new_post)
    db.session.commit()

    return jsonify({'message': 'Post created successfully'}), 201

@app.route('/delete_account', methods=['DELETE'])
@jwt_required()
def delete_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        abort(404, 'user not found')

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Account deleted successfully'}), 200

@app.route('/posts/<int:post_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def manage_post(post_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        abort(404, 'User not found')

    post = Post.query.get(post_id)

    if not post:
        abort(404, 'Post not found')

    if post.user_id != current_user_id:
        abort(403, 'You are not authorized to perform this action')

    if request.method == 'GET':
        return jsonify({
            'id': post.id,
            'content': post.content
        }), 200

    elif request.method == 'PUT':
        data = request.json

        post.content = data.get('content', post.content)

        db.session.commit()

        return jsonify({'message': 'Post updated successfully'}), 200

    elif request.method == 'DELETE':
        db.session.delete(post)
        db.session.commit()

        return jsonify({'message': 'Post deleted successfully'}), 200

@app.route('/follow/<int:user_id>', methods=['POST'])
@jwt_required()
def follow(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    target_user = User.query.get(user_id)

    if not current_user or not target_user:
        abort(404, 'User not found')

    if current_user.id == target_user.id:
        abort(400, 'Cannot follow yourself')

    follow = Follow(
        follower_id=current_user.id,
        followed_id=user_id
    )

    db.session.add(follow)
    db.session.commit()

    return jsonify({'message': 'Successfully followed'}), 200

@app.route('/unfollow/<int:user_id>', methods=['POST'])
@jwt_required()
def unfollow(user_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    target_user = User.query.get(user_id)

    if not current_user or not target_user:
        abort(404, 'User not found')

    follow = Follow.query.filter_by(
        follower_id=current_user.id,
        followed_id=user_id
    ).first()

    if not follow:
        abort(404, 'You are not following this user')

    db.session.delete(follow)
    db.session.commit()

    return jsonify({'message': 'Unfollowed successfully'}), 200

@app.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required()
def like_post(post_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    post = Post.query.get(post_id)

    if not current_user or not post:
        abort(404, 'User or Post not found')

    like = Like(
        user_id=current_user.id,
        post_id=post.id
    )

    db.session.add(like)
    db.session.commit()

    return jsonify({'message': 'Liked post'}), 200

@app.route('/posts/<int:post_id>/unlike', methods=['POST'])
@jwt_required()
def unlike_post(post_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    post = Post.query.get(post_id)

    if not current_user or not post:
        abort(404, 'User or Post not found')

    like = Like.query.filter_by(
        user_id=current_user.id,
        post_id=post.id
    ).first()

    if not like:
        abort(404, 'You have not liked this post')

    db.session.delete(like)
    db.session.commit()

    return jsonify({'message': 'Unliked post'}), 200

@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@jwt_required()
def add_comment(post_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    post = Post.query.get(post_id)

    if not current_user or not post:
        abort(404, 'User or Post not found')

    content = request.json.get('content')

    if not content:
        abort(400, 'Content is required')

    new_comment = Comment(
        user_id=current_user_id,
        post_id=post_id,
        content=content
    )

    db.session.add(new_comment)
    db.session.commit()

    return jsonify({'message': 'Comment added successfully'}), 201

@app.route('/posts/<int:post_id>/comments/<int:comment_id>', methods=['DELETE'])
@jwt_required()
def delete_comment(post_id, comment_id):
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    post = Post.query.get(post_id)

    if not current_user or not post:
        abort(404, 'User or Post not found')

    comment = Comment.query.filter_by(
        id=comment_id,
        post_id=post_id
    ).first()

    if not comment:
        abort(404, 'Comment not found')

    if comment.user_id != current_user_id:
        abort(403, 'You are not authorized to perform this action')

    db.session.delete(comment)
    db.session.commit()

    return jsonify({'message': 'Comment deleted successfully'}), 200

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/posts',methods=['GET'])
def get_posts():
    posts = Post.query.all()

    response = []
    for post in posts:
        post_data = {
            "id": post.id,
            "content": post.content,
            "likes": post.likes,
            "comments": post.comments
        }
        post_data = post.to_json()
        response.append(post_data)

    return jsonify(response), 200

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='localhost', port=5000)