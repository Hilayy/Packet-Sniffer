import firebase_admin
from firebase_admin import credentials, firestore


class DB:
    def __init__(self):
        cred = credentials.Certificate(
            r'packet-sniffer-b79f1-firebase-adminsdk-g5i8w-c5bc92d810.json')

        # Initialize the app with a service account, granting admin privileges
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://your-project-id.firebaseio.com'
        })
        self.db = firestore.client()
        self.collection = self.db.collection('users')

    def username_exists(self, username):
        query = self.collection.where('username', '==', username).limit(1)
        results = query.stream()
        for doc in results:
            return doc.to_dict()
        return None

    def add_user(self, user: dict):
        self.collection.add(user)

    def password_matches(self, user_dict, password):
        return user_dict['password'] == password






