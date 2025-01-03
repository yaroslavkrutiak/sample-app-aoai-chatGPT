def get_authenticated_user_details(request_headers):
    """Get user details from the JWT token"""
    auth_header = request_headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
        
    token = auth_header.split(' ')[1]
    payload = JWTValidator.verify_token(token)
    if not payload:
        return None
        
    return {
        'user_principal_id': payload.get('sub'),
        'user_principal_name': payload.get('email', '')
    }