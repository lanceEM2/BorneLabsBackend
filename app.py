import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
from cloudinary.uploader import upload
from dotenv import load_dotenv
from datetime import timedelta, datetime
from flask import Flask, jsonify, request, make_response, abort
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity, get_jwt
from flask_restful import Api, Resource
from flask_cors import CORS
from models import db, User, Idea, IdeaReview, Story, Message, SavedIdea, Notification, CommunityRequest, ThemeSetting, TokenBlocklist

# configuration
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = b'\xf5\x9cg|\x15\xe0\xec\x19X\r\xec\xd2\xff\x945\xb8'
app.json.compact = False

# migrating app to db
migrate = Migrate(app, db)
CORS(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = b'\x16;\x95\xda\x8d\xc19\xbal\x01\xffjL\x8e\xf8\xd4'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1) # Adjust token expiration as needed
jwt = JWTManager(app)

# Load environment variables from .env file
load_dotenv('cloudinary.env')

# Configure Cloudinary with your credentials
cloudinary.config(
  cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
  api_key = os.getenv('CLOUDINARY_API_KEY'),
  api_secret = os.getenv('CLOUDINARY_API_SECRET')
)

# initializing app
db.init_app(app)

bcrypt = Bcrypt(app)

api = Api(app)

# Creating JWT Tokens with User Type

def create_tokens(user, user_type):
    additional_claims = {'user_type': user_type}
    access_token = create_access_token(identity=str(user.id), additional_claims=additional_claims)
    return access_token

# Customer or Contributor Signup

class Signup(Resource):

    def post(self):
        data = request.form
        user_type = data.get('user_type')

        if user_type not in ['contributor']:
            return make_response(jsonify({'error': 'Invalid user type'}), 400)

        email = data['email']

        # Check if the email already exists in User table
        existing_contributor = User.query.filter_by(email=email).first()

        if existing_contributor:
            return make_response(jsonify({'message': 'This email is already in use!'}), 409)

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

        profile_image = request.files.get('image') # Accept a single image

        if not profile_image:
            abort(400, 'Image is required')

        # Upload the image to Cloudinary and store URLs
        try:
            upload_result = upload(profile_image)
            image_url = upload_result['secure_url']  # Store the secure URL
        except Exception as e:
            return {'error': f'Error uploading image: {str(e)}'}, 500

        if user_type == 'contributor':
            new_user = User(
                email=email,
                first_name = data['first_name'],
                last_name = data['last_name'],
                phone = data['phone'],
                username = data['username'],
                password_hash=hashed_password,
                profile_picture = image_url,
                bio = data['bio']
            )

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Create the JWT token
        access_token = create_tokens(new_user, user_type)

        return make_response(jsonify({'message': f'Signup successful','Authorization': access_token}), 201)

api.add_resource(Signup, "/auth/signup") 


# customer or agent login

class Login(Resource):

    def post(self):
        data = request.get_json()

        email = data['email']
        password = data['password']

        # First, try to find the user in the User table
        user = User.query.filter_by(email=email).first()
        user_type = 'contributor' if user else None

        if not user:
            abort(401, 'Invalid username or password')

        # Check the password
        if bcrypt.check_password_hash(user.password_hash, password):
            # Create the JWT token with an additional claim for user_type
            access_token = create_access_token(identity=str(user.id), additional_claims={'user_type': user_type})
            return make_response(jsonify({'message': f'{user_type.capitalize()} login successful','Authorization': access_token}), 200, )

        abort(401, 'Invalid username or password')

api.add_resource(Login, '/auth/login')


class Checksession(Resource):

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        # Check if the user is a Contributor
        user_contributor = User.query.filter_by(id=user_id).first()
        
        if user_type == "contributor" and user_contributor:
            user_data = {
                    "name": user_contributor.first_name + ' ' + user_contributor.last_name,
                    "username": user_contributor.username,
                    "phone": user_contributor.phone,
                    "email": user_contributor.email,
                    "bio": user_contributor.bio,
                    "role":"contributor"
                }
        else:
                # Handle case where the user is not found in model
                user_data = {"error": "User not found"}  
        return make_response(jsonify(user_data), 200)           

api.add_resource(Checksession,'/checksession')    
    
        
# function to enable signout

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None

# deleted from database

class Signout(Resource):

    @jwt_required()
    def delete(self):
        user_id = get_jwt_identity()
        user_type = request.json.get('user_type')

        if user_type == 'contributor':
            user = User.query.get(user_id)
        else:
            return make_response(jsonify({'error': 'Invalid user type'}), 400)

        if not user:
            return make_response(jsonify({'error': 'User not found'}), 404)

        db.session.delete(user)
        db.session.commit()

        response_dict = {'message': 'User data deleted successfully.'}
        return make_response(jsonify(response_dict), 200)

api.add_resource(Signout, '/signout')


# temporary signout

class Logout(Resource):

    @jwt_required()
    def delete(self):
        jti = get_jwt()["jti"]  # JWT ID
        user_id = get_jwt_identity()

        # Add the token to the blocklist
        token = TokenBlocklist(jti=jti, created_at=datetime.utcnow())
        db.session.add(token)
        db.session.commit()

        return make_response(jsonify({'message': 'Successfully logged out'}), 200)

api.add_resource(Logout, '/logout')


class ReviewIdeaResource(Resource):

    @jwt_required()
    def post(self, id):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        # Ensure the user is a contributor
        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        # Fetch the user from the database
        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        # Fetch the idea from the database
        idea = Idea.query.get(id)
        if not idea:
            return make_response(jsonify({'error': 'Idea not found'}), 404)

        # Check if a review already exists for the given idea by this user
        existing_review = IdeaReview.query.filter_by(reviewer_id=user_id, idea_id=id).first()
        if existing_review:
            return make_response(jsonify({'error': 'You have already reviewed this idea'}), 400)

        # Proceed to create a new review
        data = request.get_json()
        if not data or 'rating' not in data or 'comment' not in data:
            return make_response(jsonify({'error': 'Missing review data'}), 400)

        # Validate the rating (assuming it's a numeric value between 1 and 5)
        rating = data['rating']
        if not (1 <= rating <= 5):
            return make_response(jsonify({'error': 'Rating must be between 1 and 5'}), 400)

        # Determine if the user is approving
        approving = data.get('approving', False)

        # Increment the approvals count if the user is approving
        if approving:
            idea.approvals_count += 1

        # Create and save the new review
        new_review = IdeaReview(
            reviewer_id=user_id,
            idea_id=id,
            rating=rating,
            comment=data.get('comment', ''),
            approving=approving
        )
        db.session.add(new_review)
        db.session.commit()

        return make_response(jsonify({
            'message': 'Review submitted successfully',
            'approving': approving,
            'approvals_count': idea.approvals_count
        }), 201)

api.add_resource(ReviewIdeaResource, '/review/<int:id>')


class GetUserIdeaById(Resource):

    @jwt_required()
    def get(self, property_id):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        idea = Idea.query.filter_by(id=property_id, user_id=user_id).first()
        if not idea:
            return make_response(jsonify({'error': 'Idea not found'}), 404)

        return make_response(jsonify(idea.to_dict()), 200)

api.add_resource(GetUserIdeaById, '/contributor/ideas/<int:idea_id>')


# a contributor to be able to add a new idea in the system

class UserNewIdeaOrStory(Resource):

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        data = request.form

        resource_type = data.get('resource_type')  # 'idea' or 'story'
        if resource_type not in ['idea', 'story']:
            return make_response(jsonify({'error': 'Invalid resource_type. Must be "idea" or "story"'}), 400)

        # Process new idea
        if resource_type == 'idea':
            title = data.get('title')
            content = data.get('content')
            images = request.files.getlist('images')  # Expecting an array of image files

            if not title or not content:
                return make_response(jsonify({'error': 'Title and content are required'}), 400)

            if not images:
                return make_response(jsonify({'error': 'Images are required'}), 400)

            # Upload images to Cloudinary and store URLs
            image_urls = []
            for image in images:
                try:
                    upload_result = upload(image)  # Assuming `upload` is the Cloudinary upload function
                    image_urls.append(upload_result['secure_url'])  # Store secure URL
                except Exception as e:
                    return {'error': f'Error uploading image: {str(e)}'}, 500

            # Create new idea
            new_idea = Idea(
                title=title,
                content=content,
                images_url=','.join(image_urls),  # Storing the image URLs here
                user_id=user_id
            )
            db.session.add(new_idea)
            contributor.no_of_ideas += 1  # Increment the contributor's number of ideas
            db.session.commit()

            return make_response(jsonify(new_idea.to_dict()), 201)

        # Process new story
        elif resource_type == 'story':
            caption = data.get('caption')
            images = request.files.getlist('images')  # Expecting an array of image files

            if not images:
                return make_response(jsonify({'error': 'Image is required for a story'}), 400)

            # Upload the images to Cloudinary
            image_urls = []
            for image in images:
                try:
                    upload_result = upload(image)  # Assuming `upload` is the Cloudinary upload function
                    image_urls.append(upload_result['secure_url'])  # Store secure URL
                except Exception as e:
                    return {'error': f'Error uploading image: {str(e)}'}, 500

            # Create new story
            new_story = Story(
                user_id=user_id,
                caption=caption,
                images_url=','.join(image_urls),  # Storing the image URLs here
            )
            db.session.add(new_story)
            db.session.commit()

            return make_response(jsonify(new_story.to_dict()), 201)

api.add_resource(UserNewIdeaOrStory, '/resources/add')


class UserUpdateIdeaOrStory(Resource):

    @jwt_required()
    def patch(self):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributor only'}), 403)

        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        data = request.form
        resource_type = data.get('resource_type')
        resource_id = data.get('resource_id')

        if not resource_id or not resource_type:
            return {'error': 'resource_type and resource_id are required'}, 400

        # Retrieve the resource
        if resource_type == 'idea':
            resource = Idea.query.filter_by(id=resource_id, user_id=user_id).first()
        elif resource_type == 'story':
            resource = Story.query.filter_by(id=resource_id, user_id=user_id).first()
        else:
            return {'error': 'Invalid resource type'}, 400

        if not resource:
            return {'error': f'{resource_type.capitalize()} with id {resource_id} not found'}, 404

         # Update fields dynamically
        for field, value in data.items():
            if not value:  # Skip empty values
                continue

            if field in ['created_at', 'updated_at']:  # Handle DateTime fields
                if hasattr(resource, field):
                    try:
                        value = datetime.strptime(value, "%a, %d %b %Y %H:%M:%S %Z")
                        setattr(resource, field, value)
                    except ValueError:
                        return {'error': f'Invalid datetime format for field {field}'}, 400
                continue

            if hasattr(resource, field) and field != 'id':  # Dynamically update other fields
                setattr(resource, field, value)

        # Handle image uploads
        if 'images' in request.files:  # Check if new images are provided
            images = request.files.getlist('images')  # Get the list of images
            new_image_urls = []
            for image in images:
                try:
                    upload_result = cloudinary.uploader.upload(image)  # Upload image to Cloudinary
                    new_image_urls.append(upload_result['secure_url'])
                except Exception as e:
                    print(f"Error uploading image: {str(e)}")
                    return {'error': f'Error uploading image: {str(e)}'}, 500

            # Replace existing images with new ones
            resource.images_url = ','.join(new_image_urls)
        else:
            # No new images provided; retain existing images
            print("No new images provided; keeping existing images.")

        # Commit changes to the database
        try:
            db.session.commit()
            print("Database commit successful.")
        except Exception as e:
            print("Error during database commit:", str(e))
            return {'error': 'Failed to save changes to the database'}, 500

        return make_response(jsonify(resource.to_dict()), 200)

api.add_resource(UserUpdateIdeaOrStory, '/resources/update')


# a contributor to be able to delete an idea he/she owns

class UserDeleteIdeaOrStory(Resource):

    @jwt_required()
    def delete(self):

        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        data = request.get_json()

        resource_type = data.get('resource_type')
        resource_id = data.get('resource_id')
        if not resource_type or not resource_id:
            abort(400, 'resource_type and resource_id are required in the request')

        if resource_type == 'idea':
            resource = Idea.query.filter_by(id=resource_id, user_id=user_id).first()
        elif resource_type == 'story':
            resource = Story.query.filter_by(id=resource_id, user_id=user_id).first()
        else:
            abort(400, 'Invalid resource type')

        if not resource:
            abort(404, f'{resource_type.capitalize()} with id {resource_id} not found')

        db.session.delete(resource)

        # Decrement the contributor's `no_of_ideas` only if the resource type is 'idea'
        if resource_type == 'idea':
            contributor.no_of_ideas -= 1

        db.session.commit()

        response_dict = {"message": f"{resource_type.capitalize()} successfully deleted"}

        return make_response(jsonify(response_dict), 200)

api.add_resource(UserDeleteIdeaOrStory, '/resources/delete')


# an agent to be able to view his/her data(profile) included with properties and lands

class GetUserData(Resource):

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        agent_data = contributor.to_dict()

        return make_response(jsonify(agent_data), 200)

api.add_resource(GetUserData, '/contributor-data')


# an agent is able to update his/her data(profile)

class UpdateUserData(Resource):

    @jwt_required()
    def patch(self):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')

        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributor only'}), 403)

        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        data = request.form

        if not data:
            return make_response(jsonify({'error': 'No data provided'}), 400)

        for attr, value in data.items():
            if attr == 'password':
                value = bcrypt.generate_password_hash(value)
            if value and hasattr(contributor, attr):  # Update only if the value is provided
                setattr(contributor, attr, value)

        # Handle profile picture upload
        if 'image' in request.files:  # Check if a new profile picture is provided
            image = request.files.get('image')
            try:
                # Upload the image to Cloudinary
                upload_result = cloudinary.uploader.upload(image)
                contributor.profile_picture = upload_result['secure_url']  # Update profile picture URL
            except Exception as e:
                print(f"Error uploading profile picture: {str(e)}")
                return {'error': f'Error uploading profile picture: {str(e)}'}, 500

        # Commit changes to the database
        try:
            db.session.commit()
        except Exception as e:
            print(f"Error during database commit: {str(e)}")
            return {'error': 'Failed to save changes to the database'}, 500

        # Prepare the response
        response_dict = contributor.to_dict()

        return make_response(jsonify(response_dict), 200)

api.add_resource(UpdateUserData, '/contributor-data/update')


# gets/fetches all ideas - to be viewed by everyone
# frontend example /resources?resource_type=ideas&page=1&per_page=5

class GetIdeasOrStories(Resource):

    def get(self):
        # Get the pagination parameters from the query string
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 8, type=int)  # Default to 10 items per page
        resource_type = request.args.get('resource_type')

        if not resource_type:
            return make_response(jsonify({'error': 'resource_type is required (e.g., "ideas" or "stories")'}), 400)

        if resource_type == 'ideas':
            resource_query = Idea.query
        elif resource_type == 'stories':
            resource_query = Story.query
        else:
            return make_response(jsonify({'error': f'Invalid resource_type: {resource_type}'}), 400)

        # Paginate the query
        paginated_resources = resource_query.paginate(page=page, per_page=per_page, error_out=False)

        # Check if there are resources to display
        if not paginated_resources.items:
            return make_response(jsonify({'error': f'No {resource_type} found'}), 404)

        # Convert the resources to dictionaries
        resource_data = [resource_instance.to_dict() for resource_instance in paginated_resources.items]

        # Prepare the response with pagination metadata
        response = {
            'total': paginated_resources.total,
            'pages': paginated_resources.pages,
            'current_page': paginated_resources.page,
            'next_page': paginated_resources.next_num if paginated_resources.has_next else None,
            'prev_page': paginated_resources.prev_num if paginated_resources.has_prev else None,
            'per_page': paginated_resources.per_page,
            'data': resource_data
        }

        return make_response(jsonify(response), 200)

api.add_resource(GetIdeasOrStories, '/resources')        


# gets all ideas according to title(robotics or technology)

class GetIdeasByTitle(Resource):

    def get(self, title):
        valid_titles = ['technology', 'robotics']
        
        if title not in valid_titles:
            abort(404, 'Invalid title')

        resource_instances = Idea.query.filter_by(title=title).all()

        if not resource_instances:
            abort(404, f'No ideas found for {title}')

        resource_data = [resource_instance.to_dict() for resource_instance in resource_instances]

        return make_response(jsonify(resource_data), 200)

api.add_resource(GetIdeasByTitle, '/ideas/<string:title>')


# gets all ideas according to tier(Concept, Community, Prototype, Innovation, Masterpiece)

class GetIdeasByTier(Resource):

    def get(self, tier):
        valid_tiers = ['Concept', 'Community', 'Prototype', 'Innovation', 'Masterpiece']
        
        if tier not in valid_tiers:
            abort(404, 'Invalid tier')

        resource_instances = Idea.query.filter_by(tier=tier).all()

        if not resource_instances:
            abort(404, f'No ideas found for {tier}')

        resource_data = [resource_instance.to_dict() for resource_instance in resource_instances]

        return make_response(jsonify(resource_data), 200)

api.add_resource(GetIdeasByTier, '/ideas/<string:tier>')


# gets idea by id

class GetIdeaById(Resource):

    def get(self, idea_id):
        # Query the Idea by its id
        idea_instance = Idea.query.get(idea_id)

        # If no idea is found, return a 404 error
        if not idea_instance:
            abort(404, f'Idea with id {idea_id} not found')

        # Convert the idea instance to a dictionary
        idea_data = idea_instance.to_dict()

        # Return the idea data as a JSON response
        return make_response(jsonify(idea_data), 200)

api.add_resource(GetIdeaById, '/ideas/id/<int:idea_id>')


# gets all contributors in the system 

class GetUsers(Resource):

    def get(self):

        all_contributors = User.query.all()
        if not all_contributors:
            abort(404, 'No contributors found')

        contributors = []

        for contributor_instance in all_contributors:
            contributor_data = contributor_instance.to_dict()

            contributors.append(contributor_data)

        return make_response(jsonify(contributors), 200)

api.add_resource(GetUsers, '/contributors')


class UpdateIdeaReviewResource(Resource):

    @jwt_required()
    def put(self, id):
        user_id = get_jwt_identity()
        user_type = get_jwt().get('user_type')  # Check user type

        # Ensure the user is a contributor
        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        # Fetch the user from the database
        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        # Fetch the review from the database
        review = IdeaReview.query.filter_by(reviewer_id=user_id, idea_id=id).first()
        if not review:
            return make_response(jsonify({'error': 'Review not found'}), 404)

        # Fetch the idea associated with the review
        idea = Idea.query.get(id)
        if not idea:
            return make_response(jsonify({'error': 'Idea not found'}), 404)

        # Get the request data
        data = request.get_json()
        if not data:
            return make_response(jsonify({'error': 'No data provided'}), 400)

        # Update the review fields
        if 'rating' in data:
            rating = data['rating']
            if not (1 <= rating <= 5):  # Validate rating
                return make_response(jsonify({'error': 'Rating must be between 1 and 5'}), 400)
            review.rating = rating

        if 'comment' in data:
            review.comment = data['comment']

        if 'approving' in data:
            approving = data['approving']
            if isinstance(approving, bool):
                if approving != review.approving:
                    # Update the approvals count if contribution status changes
                    if approving and not review.approving:
                        idea.approvals_count += 1
                    elif not approving and review.approving:
                        idea.approvals_count -= 1

                    # Update the approving status in the review
                    review.approving = approving
            else:
                return make_response(jsonify({'error': 'approving must be a boolean value'}), 400)

        # Commit the changes to the database
        try:
            db.session.commit()
        except Exception as e:
            print(f"Error during database commit: {str(e)}")
            return make_response(jsonify({'error': 'Failed to update review'}), 500)

        return make_response(jsonify({
            'message': 'Review updated successfully',
            'approving': review.approving,
            'approvals_count': idea.approvals_count
        }), 200)

api.add_resource(UpdateIdeaReviewResource, '/review/<int:id>/update')        


class DeleteIdeaReviewResource(Resource):

    @jwt_required()
    def delete(self, id):
        user_id = get_jwt_identity()  
        user_type = get_jwt().get('user_type')  # Check user type

        # Ensure the user is a contributor
        if user_type != 'contributor':
            return make_response(jsonify({'error': 'Access forbidden: Contributors only'}), 403)

        # Fetch the user from the database
        contributor = User.query.get(user_id)
        if not contributor:
            return make_response(jsonify({'error': 'User not found'}), 404)

        # Fetch the review from the database
        review = IdeaReview.query.filter_by(reviewer_id=user_id, idea_id=id).first()
        if not review:
            return make_response(jsonify({'error': 'Review not found'}), 404)

        # Fetch the idea associated with the review
        idea = Idea.query.get(id)
        if not idea:
            return make_response(jsonify({'error': 'Idea not found'}), 404)

        # Delete the review
        db.session.delete(review)
        db.session.commit()

        return make_response(jsonify({'message': 'Review deleted successfully'}), 200)

api.add_resource(DeleteIdeaReviewResource, '/review/<int:id>/delete')


class UserMessageResource(Resource):
    
    @jwt_required()
    def post(self):
        sender_id = get_jwt_identity()

        # Parse the JSON payload
        data = request.get_json()
        
        receiver_id = data.get('receiver_id')
        content = data.get('content')

        # Validate required fields
        if not receiver_id or not content:
            return make_response(jsonify({'error': 'receiver_id and content are required'}), 400)

        # Ensure sender and receiver are not the same
        if str(sender_id) == str(receiver_id):  # Ensure strict type checking
            return make_response(jsonify({'error': 'You cannot send a message to yourself'}), 400)

        # Check if sender exists
        sender = User.query.get(sender_id)
        if not sender:
            return make_response(jsonify({'error': 'Sender not found'}), 404)

        # Check if receiver exists
        receiver = User.query.get(receiver_id)
        if not receiver:
            return make_response(jsonify({'error': 'Receiver not found'}), 404)

        # Create the message
        new_message = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            content=content,
            is_read=False
        )

        db.session.add(new_message)

        # Create a notification for the receiver
        notification = Notification(
            user_id=receiver_id,
            message=f"You have a new message from {sender.username}",
            timestamp=datetime.utcnow(),
            is_read=False
        )
        db.session.add(notification)

        db.session.commit()

        return make_response(jsonify({'message': 'Message sent successfully', 'data': new_message.to_dict()}), 201)

api.add_resource(UserMessageResource, '/messages/send')


class UserUpdateMessageResource(Resource):

    @jwt_required()
    def put(self, message_id):
        user_id = get_jwt_identity()

        # Find the message in the database
        message = Message.query.filter_by(id=message_id, sender_id=user_id).first()

        if not message:
            return make_response(jsonify({'error': 'Message not found or access forbidden'}), 404)

        # Check if the message has already been read
        if message.is_read:
            return make_response(jsonify({'error': 'Cannot edit a message that has already been read by the receiver'}), 400)

        # Check if the message was sent more than 5 minutes ago
        time_elapsed = datetime.utcnow() - message.timestamp
        if time_elapsed.total_seconds() > 300:
            return make_response(jsonify({'error': 'Cannot edit a message after 5 minutes of sending'}), 400)

        # Parse the JSON payload
        data = request.get_json()
        new_content = data.get('content')

        if not new_content:
            return make_response(jsonify({'error': 'New content is required'}), 400)

        # Update the message content
        message.content = new_content
        db.session.commit()

        return make_response(jsonify({'message': 'Message updated successfully', 'data': message.to_dict()}), 200)

api.add_resource(UserUpdateMessageResource, '/messages/update/<int:message_id>')


class UserDeleteMessageResource(Resource):

    @jwt_required()
    def delete(self, message_id):
        user_id = get_jwt_identity()

        # Find the message in the database
        message = Message.query.filter_by(id=message_id, sender_id=user_id).first()

        if not message:
            return make_response(jsonify({'error': 'Message not found or access forbidden'}), 404)

        # Delete the message
        db.session.delete(message)
        db.session.commit()

        return make_response(jsonify({'message': 'Message deleted successfully'}), 200)

api.add_resource(UserDeleteMessageResource, '/messages/delete/<int:message_id>')


class MessageStatusResource(Resource):
    
    @jwt_required()
    def put(self, message_id):
        user_id = get_jwt_identity()

        # Fetch the message
        message = Message.query.filter_by(id=message_id, receiver_id=user_id).first()

        if not message:
            return make_response(jsonify({'error': 'Message not found or access forbidden'}), 404)

        # Update message's is_read status
        if not message.is_read:
            message.is_read = True

            # Update the notification associated with the message
            notification = Notification.query.filter_by(user_id=user_id).first()

            if notification and not notification.is_read:
                notification.is_read = True

            db.session.commit()

        return make_response(jsonify({'message': 'Message status updated successfully'}), 200)

api.add_resource(MessageStatusResource, '/messages/<int:message_id>/read')


class UnreadMessagesResource(Resource):
    
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()

        # Fetch all unread messages for the user
        unread_messages = Message.query.filter_by(receiver_id=user_id, is_read=False).all()

        if not unread_messages:
            return make_response(jsonify({'message': 'No unread messages'}), 200)

        return make_response(jsonify({
            'message': 'Unread messages fetched successfully',
            'data': [message.to_dict() for message in unread_messages]
        }), 200)

api.add_resource(UnreadMessagesResource, '/messages/unread')


class UnreadNotificationsResource(Resource):
    
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()

        # Fetch all unread notifications for the user
        unread_notifications = Notification.query.filter_by(user_id=user_id, is_read=False).all()

        if not unread_notifications:
            return make_response(jsonify({'message': 'No unread notifications'}), 200)

        return make_response(jsonify({
            'message': 'Unread notifications fetched successfully',
            'data': [notification.to_dict() for notification in unread_notifications]
        }), 200)

api.add_resource(UnreadNotificationsResource, '/notifications/unread')


class SaveIdeaResource(Resource):

    @jwt_required()
    def post(self, idea_id):
        user_id = get_jwt_identity()

        # Check if the idea exists
        idea = Idea.query.get(idea_id)
        if not idea:
            return make_response(jsonify({'error': 'Idea not found'}), 404)

        # Check if the idea is already saved by the user
        existing_saved_idea = SavedIdea.query.filter_by(user_id=user_id, idea_id=idea_id).first()
        if existing_saved_idea:
            return make_response(jsonify({'error': 'Idea already saved'}), 400)

        # Save the idea
        saved_idea = SavedIdea(user_id=user_id, idea_id=idea_id)
        db.session.add(saved_idea)
        db.session.commit()

        return make_response(jsonify({'message': 'Idea saved successfully', 'saved_idea': saved_idea.to_dict()}), 201)

api.add_resource(SaveIdeaResource, '/save_idea/<int:idea_id>/add')


class DeleteSavedIdeaResource(Resource):

    @jwt_required()
    def delete(self, idea_id):
        user_id = get_jwt_identity()

        # Check if the idea is saved by the user
        saved_idea = SavedIdea.query.filter_by(user_id=user_id, idea_id=idea_id).first()
        if not saved_idea:
            return make_response(jsonify({'error': 'Saved idea not found'}), 404)

        # Delete the saved idea
        db.session.delete(saved_idea)
        db.session.commit()

        return make_response(jsonify({'message': 'Saved idea deleted successfully'}), 200)

api.add_resource(DeleteSavedIdeaResource, '/saved_ideas/<int:idea_id>/delete')        


class SavedIdeaResource(Resource):
    
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()

        # Fetch all saved ideas by the user
        saved_ideas = SavedIdea.query.filter_by(user_id=user_id).all()

        if not saved_ideas:
            return make_response(jsonify({'message': 'No Saved ideas'}), 200)

        return make_response(jsonify({
            'message': 'Saved ideas fetched successfully',
            'data': [idea.to_dict() for idea in saved_ideas]
        }), 200)

api.add_resource(SavedIdeaResource, '/saved_ideas')


class SavedIdeaByIdResource(Resource):
    
    @jwt_required()
    def get(self, idea_id):
        user_id = get_jwt_identity()

        # Fetch all saved ideas by the user
        saved_ideas = SavedIdea.query.filter_by(user_id=user_id, idea_id=idea_id).all()

        if not saved_ideas:
            return make_response(jsonify({'message': 'No Saved ideas'}), 200)

        return make_response(jsonify({
            'message': 'Saved ideas fetched successfully',
            'data': [idea.to_dict() for idea in saved_ideas]
        }), 200)

api.add_resource(SavedIdeaByIdResource, '/saved_ideas/<int:idea_id>')


class AskApproveIdeaResource(Resource):

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()  # Get the ID of the current user
        
        # Parse the request JSON
        data = request.get_json()
        idea_id = data.get('idea_id')
        if not idea_id:
            return make_response(jsonify({'error': 'idea_id is required'}), 400)

        # Fetch the idea
        idea = Idea.query.get(idea_id)
        if not idea:
            return make_response(jsonify({'error': 'Idea not found'}), 404)

        # Ensure the current user is not trying to approve their own idea
        if str(idea.user_id) == str(user_id):
            return make_response(jsonify({'error': 'You cannot approve your own idea'}), 400)

        # Create a community request message
        approval_message = f"Your idea '{idea.title}' has been marked for approval by user {user_id}."

        # Add the request to the CommunityRequest table
        community_request = CommunityRequest(
            user_id=idea.user_id,
            message=approval_message,
            status="Pending"
        )
        db.session.add(community_request)

        # Send a notification to the idea's owner
        notification_message = f"User {user_id} has requested approval for your idea: '{idea.title}'."
        notification = Notification(
            user_id=idea.user_id,
            message=notification_message
        )
        db.session.add(notification)

        db.session.commit()

        return make_response(jsonify({
            "message": "Approval request sent successfully",
            "community_request": community_request.to_dict(),
            "notification": notification.to_dict()
        }), 201)

api.add_resource(AskApproveIdeaResource, '/ideas/ask-approve')


class PendingCommunityRequests(Resource):

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()

        # Fetch all pending community requests for the user
        community_requests = CommunityRequest.query.filter_by(user_id=user_id, status="Pending").all()

        if not community_requests:
            return make_response(jsonify({'message': 'No pending community requests'}), 200)

        return make_response(jsonify({
            "message": "Pending community requests fetched successfully.",
            "requests": [req.to_dict() for req in community_requests]
        }), 200)

api.add_resource(PendingCommunityRequests, '/community/pending-requests')


class HandleCommunityRequests(Resource):

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()

        data = request.get_json()
        request_id = data.get("request_id")
        action = data.get("action")  # "approve", "decline", or None (leave as "Pending")

        if not request_id:
            return make_response(jsonify({'error': 'request_id is required'}), 400)

        # Fetch the community request
        community_request = CommunityRequest.query.get(request_id)
        if not community_request:
            return make_response(jsonify({'error': 'Request not found'}), 404)

        # Ensure the user has the authority to process the request
        if str(community_request.user_id) != str(user_id):
            return make_response(jsonify({'error': 'Unauthorized to process this request'}), 403)

        # Process the action
        if action == "approve":
            community_request.status = "Approved"

            # Send a message to the requester
            approval_message = "Your community request has been approved!"
            message = Message(
                sender_id=user_id,
                receiver_id=community_request.user_id,
                content=approval_message
            )
            db.session.add(message)

            # Send a notification to the requester
            notification = Notification(
                user_id=community_request.user_id,
                message="Your community request has been approved."
            )
            db.session.add(notification)

        elif action == "decline":
            community_request.status = "Rejected"

        # Mark the notification about this request as read
        related_notification = Notification.query.filter_by(
            user_id=user_id, message=community_request.message
        ).first()

        if related_notification:
            related_notification.is_read = True

        db.session.commit()

        return make_response(jsonify({
            "message": f"Community request has been {community_request.status.lower()}",
            "request": community_request.to_dict()
        }), 200)

api.add_resource(HandleCommunityRequests, '/community/handle-requests')        


if __name__ == '__main__':
    app.run(port=5556, debug=True)