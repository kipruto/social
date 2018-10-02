from functools import wraps
from flask import abort
from flask_login import current_user
from .models import Permission

# Custom decorators for cases where an entire route needs to be made available
# only to users with certain permissions


# Generic permission checks decorator
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.can(permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Administrator permission check
def admin_required(f):
    return permission_required(Permission.ADMIN)(f)
