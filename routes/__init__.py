"""
Routes package - contains all API route blueprints.

Blueprints are registered with the main app via register_blueprints().
"""

from .chaos import chaos_bp
from .auth_routes import auth_routes_bp
from .dns import dns_bp
from .whois import whois_bp


def register_blueprints(app):
    """Register all route blueprints with the Flask app."""
    app.register_blueprint(auth_routes_bp)
    app.register_blueprint(dns_bp)
    app.register_blueprint(whois_bp)
    app.register_blueprint(chaos_bp)
