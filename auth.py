import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta

class AuthHandler():
	security = HTTPBearer()
	pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")
	secret = 'f3f968887272475f8dd87036cab6e02e7b0beb0399c1c55890902595a8fb52e5'

	def get_password_hash(self, password):
		return self.pwd_context.hash(password)

	def verify_password(self, plain_password, hashed_password):
		return self.pwd_context.verify(plain_password, hashed_password)

	def encode_token(self, user_id):
		payload = {
			'exp': datetime.utcnow() + timedelta(days=0, minutes=5),
			'iat': datetime.utcnow(),
			'sub': user_id
		}
		return jwt.encode(
			payload,
			self.secret,
			algorithm='HS256'
		)

	def decode_token(self, token):
		try:
			payload = jwt.decode(token, self.secret, algorithms=['HS256'])
			return payload['sub']
		except jwt.ExpiredSignatureError:
			raise HTTPException(status_code=401, detail = 'signture has expired')
		except jwt.InvalidTokenError as e:
			raise HTTPException(status_code=401, detail = 'Invalid Token')

	def auth_wrapper(self,auth: HTTPAuthorizationCredentials = Security(security)):
		return self.decode_token(auth.credentials)
