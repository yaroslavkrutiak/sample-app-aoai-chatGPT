from jose import jwt, JWTError
from quart import Request
import logging
from backend.settings import app_settings
from datetime import datetime

class JWTValidator:
    @staticmethod
    def verify_token(token: str) -> dict:
        """Verify the JWT token from NestJS backend"""
        try:
            payload = jwt.decode(
                token,
                app_settings.base_settings.jwt_secret,
                algorithms=['HS256']
            )
            
            # Verify expiration
            if 'exp' in payload:
                exp = datetime.fromtimestamp(payload['exp'])
                if datetime.utcnow() > exp:
                    return None
            
            return payload
        except JWTError as e:
            logging.error(f"JWT verification failed: {str(e)}")
            return None