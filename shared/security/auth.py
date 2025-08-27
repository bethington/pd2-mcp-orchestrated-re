"""
Authentication and authorization utilities
"""

import os
import jwt
import logging
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Callable
from flask import request, jsonify

logger = logging.getLogger(__name__)


class AuthManager:
    """Manages authentication tokens and user sessions"""
    
    def __init__(self, secret_key: Optional[str] = None, expiry_hours: int = 24):
        self.secret_key = secret_key or os.getenv('JWT_SECRET_KEY', 'change-me-in-production')
        self.expiry_hours = expiry_hours
        self.algorithm = 'HS256'
        
        if self.secret_key == 'change-me-in-production':
            logger.warning("Using default JWT secret key - change in production!")
    
    def generate_token(self, user_id: str, permissions: List[str] = None) -> str:
        """Generate a JWT token for a user"""
        payload = {
            'user_id': user_id,
            'permissions': permissions or [],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.expiry_hours)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        logger.info(f"Generated token for user: {user_id}")
        return token
    
    def validate_token(self, token: str) -> Dict:
        """Validate and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token validation failed: expired")
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {e}")
            raise AuthenticationError("Invalid token")
    
    def refresh_token(self, token: str) -> str:
        """Refresh an existing token"""
        payload = self.validate_token(token)
        user_id = payload['user_id']
        permissions = payload.get('permissions', [])
        return self.generate_token(user_id, permissions)


class JWTValidator:
    """JWT token validation utilities"""
    
    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
    
    def extract_token(self, request) -> Optional[str]:
        """Extract JWT token from request headers"""
        auth_header = request.headers.get('Authorization', '')
        
        if auth_header.startswith('Bearer '):
            return auth_header[7:]  # Remove 'Bearer ' prefix
        
        return None
    
    def validate_request(self, request) -> Dict:
        """Validate JWT token from request and return payload"""
        token = self.extract_token(request)
        
        if not token:
            raise AuthenticationError("No authentication token provided")
        
        return self.auth_manager.validate_token(token)


def require_auth(permissions: List[str] = None):
    """
    Decorator to require authentication for API endpoints
    
    Args:
        permissions: List of required permissions
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Get auth manager from app config
                auth_manager = AuthManager()
                validator = JWTValidator(auth_manager)
                
                # Validate token and get user info
                payload = validator.validate_request(request)
                
                # Check permissions if specified
                if permissions:
                    user_permissions = payload.get('permissions', [])
                    if not all(perm in user_permissions for perm in permissions):
                        logger.warning(f"Permission denied for user {payload.get('user_id')}: "
                                     f"required={permissions}, has={user_permissions}")
                        return jsonify({'error': 'Insufficient permissions'}), 403
                
                # Add user info to request context
                request.user_id = payload['user_id']
                request.permissions = payload.get('permissions', [])
                
                return f(*args, **kwargs)
                
            except AuthenticationError as e:
                logger.warning(f"Authentication failed: {e}")
                return jsonify({'error': str(e)}), 401
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                return jsonify({'error': 'Authentication failed'}), 500
        
        return decorated_function
    return decorator


class AuthenticationError(Exception):
    """Authentication-related error"""
    pass


class PermissionManager:
    """Manages user permissions and roles"""
    
    PERMISSIONS = {
        # Analysis permissions
        'analysis:read': 'View analysis results',
        'analysis:write': 'Create and modify analyses',
        'analysis:delete': 'Delete analyses',
        
        # Memory permissions
        'memory:read': 'Read memory dumps',
        'memory:analyze': 'Analyze memory contents',
        'memory:dump': 'Create memory dumps',
        
        # Game permissions
        'game:monitor': 'Monitor game state',
        'game:control': 'Control game actions',
        'game:debug': 'Access game debugging features',
        
        # System permissions
        'system:admin': 'System administration',
        'system:config': 'Modify system configuration',
        'system:logs': 'Access system logs',
        
        # Data permissions
        'data:export': 'Export data and reports',
        'data:import': 'Import external data',
        'data:backup': 'Create and restore backups',
    }
    
    ROLES = {
        'analyst': [
            'analysis:read', 'analysis:write',
            'memory:read', 'memory:analyze',
            'game:monitor', 'data:export'
        ],
        'researcher': [
            'analysis:read', 'analysis:write', 'analysis:delete',
            'memory:read', 'memory:analyze', 'memory:dump',
            'game:monitor', 'game:debug',
            'data:export', 'data:import'
        ],
        'admin': list(PERMISSIONS.keys()),  # All permissions
        'viewer': [
            'analysis:read', 'memory:read', 'game:monitor'
        ]
    }
    
    @classmethod
    def get_role_permissions(cls, role: str) -> List[str]:
        """Get permissions for a role"""
        return cls.ROLES.get(role, [])
    
    @classmethod
    def validate_permissions(cls, permissions: List[str]) -> List[str]:
        """Validate and filter permissions"""
        return [perm for perm in permissions if perm in cls.PERMISSIONS]