from flask import Flask, jsonify, request
from flask_mongoengine import MongoEngine
from mongoengine import Document, StringField, EmailField, ReferenceField
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['MONGODB_SETTINGS'] = {
    'host': 'mongodb://localhost:27017/blog'
}
app.config['JWT_SECRET_KEY'] = 'adslfkjdlskajflkjlkasdfjklsajdflkjsdflksklafjklsajflksjflksjfklfjsa'

db = MongoEngine(app)
jwt = JWTManager(app)


class User(Document):
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)


class Post(Document):
    title = StringField(required=True)
    content = StringField(required=True)
    author = ReferenceField(User)


class UserController:
    @staticmethod
    def login():
        email = request.json.get('email')
        password = request.json.get('password')

        if not email or not password:
            return jsonify(message='email and password field are needed', success=False), 403
        else:
            user = User.objects(email=email).first()
            if not user or not check_password_hash(user.password, password):
                return jsonify(message='Invalid Credentials', success=False), 401

            access_token = create_access_token(identity=user.email)
            return jsonify(access_token=access_token), 200

    @staticmethod
    def register():
        email = request.json.get('email')
        password = request.json.get('password')

        if not email or not password:
            return jsonify(message='email and password field are needed', success=False), 403
        else:
            user = User.objects(email=email).first()
            if user:
                return jsonify(message='user already created with this email', success=False), 403

            hash_password = generate_password_hash(password)
            user = User(email=email, password=hash_password)
            user.save()
            print(user)
            return jsonify(message='user created!'), 201


class PostsController:
    @staticmethod
    # @jwt_required
    def create_post():
        # current_user = get_jwt_identity()
        title = request.json.get('title')
        content = request.json.get('content')
        author = request.json.get('author')

        if not title or not content or not author:
            return jsonify(message='title, content and author field are needed to crate a post', success=False), 403
        else:
            # author = User.objects(id=current_user).first()
            body = request.get_json()
            post = Post(**body).save()
            # post = Post(title=title, content=content, author=author)
            # post.save()
            return jsonify(message='Post created!', success=True, data=post), 201

    @staticmethod
    def get_posts():
        all_posts = list(Post.objects)
        return jsonify(all_posts), 200

    @staticmethod
    def get_post(post_id):
        post = Post.objects(id=post_id).first()
        if post is None:
            return jsonify(message='Post not found'), 404
        return jsonify(post), 200

    @staticmethod
    def update(post_id):
        title = request.json.get('title')
        content = request.json.get('content')
        # author = request.json.get('author')

        if not title or not content:
            return jsonify(message='title and content field are needed to crate a post', success=False), 403
        else:
            post = Post.objects(id=post_id)
            if post:
                body = request.get_json()
                post.update(**body)
                return jsonify(message="post updated", success=True), 200
            else:
                return jsonify(message='post not found', success=False), 403

    @staticmethod
    def delete(post_id):
        post = Post.objects(id=post_id).first()
        if post:
            Post.objects(id=post_id).first().delete()
            return jsonify(message='post deleted', success=True), 200
        else:
            return jsonify(message='post not found', success=False), 403


app.add_url_rule('/api/user/login', 'login',
                 UserController.login, methods=['POST'])
app.add_url_rule('/api/user/register', 'register',
                 UserController.register, methods=['POST'])
app.add_url_rule('/api/posts', 'create_post',
                 PostsController.create_post, methods=['POST'])
app.add_url_rule('/api/posts', 'get_posts',
                 PostsController.get_posts, methods=['GET'])
app.add_url_rule('/api/posts/<string:post_id>', 'get_post',
                 PostsController.get_post, methods=['GET'])
app.add_url_rule('/api/posts/<string:post_id>', 'update_post',
                 PostsController.update, methods=['PUT'])
app.add_url_rule('/api/posts/<string:post_id>', 'delete_post',
                 PostsController.delete, methods=['DELETE'])

if __name__ == '__main__':
    app.run(debug=True)
