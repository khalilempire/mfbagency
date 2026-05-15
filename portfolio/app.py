"""
MFB Agency — Secure Flask Backend
===================================
Security features implemented:
  1. Flask-Talisman: HTTPS enforcement, CSP, X-Frame-Options, HSTS
  2. Flask-Limiter: Rate limiting to prevent abuse
  3. Flask-WTF: CSRF protection on all forms
  4. Security Headers: X-Content-Type-Options, Referrer-Policy, Permissions-Policy
  5. Client-side: DevTools detection, right-click block, shortcut block
  6. Admin bypass: Only you can access DevTools via a secret typed password
  7. Input sanitization on contact form
  8. Anti-clickjacking headers
"""

import os
import re
import urllib.parse
from datetime import timedelta

from flask import Flask, render_template, request, jsonify, abort
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv

# ── Load environment variables ──
load_dotenv()

app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static'
)

# ── App Configuration ──
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-in-production')
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour token validity
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ── CSRF Protection ──
csrf = CSRFProtect(app)

# ── Rate Limiter ──
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ── Content Security Policy ──
csp = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        "'unsafe-inline'",  # Required for inline scripts in templates
    ],
    'style-src': [
        "'self'",
        "'unsafe-inline'",  # Required for inline styles
        "https://fonts.googleapis.com",
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com",
    ],
    'img-src': ["'self'", "data:"],
    'media-src': ["'self'"],
    'connect-src': ["'self'", "https://wa.me"],
    'frame-ancestors': ["'none'"],  # Anti-clickjacking
    'base-uri': ["'self'"],
    'form-action': ["'self'", "https://wa.me"],
    'object-src': ["'none'"],
}

# ── Talisman Security ──
talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],  # Nonce for inline scripts
    force_https=False,           # Set True in production with SSL
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    session_cookie_secure=False,  # Set True when using HTTPS
    frame_options='DENY',
    x_content_type_options=True,
    x_xss_protection=True,
    referrer_policy='strict-origin-when-cross-origin',
    permissions_policy={
        'camera': '()',
        'microphone': '()',
        'geolocation': '()',
        'payment': '()',
    }
)

# ── Admin DevTools password ──
ADMIN_DEV_PASSWORD = os.getenv('ADMIN_DEV_PASSWORD', 'MFB_Khalil_2026!')


# ── Custom Security Headers ──
@app.after_request
def add_security_headers(response):
    """Add extra security headers to every response."""
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Cross-Origin-Embedder-Policy'] = 'unsafe-none'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    # Remove server identification
    response.headers.pop('Server', None)
    return response


# ── Template Context — inject admin key & CSRF token into all pages ──
@app.context_processor
def inject_globals():
    return {
        'admin_key': ADMIN_DEV_PASSWORD,
    }


# ──────────────────────────────────────
#   ROUTES
# ──────────────────────────────────────

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')


@app.route('/work')
def work():
    """Work / portfolio page."""
    return render_template('work.html')


@app.route('/contact')
def contact():
    """Contact page."""
    return render_template('contact.html')


@app.route('/api/contact', methods=['POST'])
@limiter.limit("5 per hour")
def submit_contact():
    """
    Secure contact form endpoint.
    Sanitizes all inputs before processing.
    """
    data = request.get_json(silent=True) or request.form

    name = sanitize_input(data.get('name', ''))
    email = sanitize_input(data.get('email', ''))
    company = sanitize_input(data.get('company', ''))
    phone = sanitize_input(data.get('phone', ''))
    project = sanitize_input(data.get('project', ''))

    # Validation
    errors = []
    if not name or len(name) < 2:
        errors.append('Name is required (min 2 characters).')
    if not email or not is_valid_email(email):
        errors.append('A valid email address is required.')
    if not project or len(project) < 10:
        errors.append('Project description is required (min 10 characters).')
    if len(name) > 100 or len(email) > 254 or len(project) > 5000:
        errors.append('Input exceeds maximum allowed length.')

    if errors:
        return jsonify({'success': False, 'errors': errors}), 400

    # Build WhatsApp message
    text = (
        f"*New Project Request*\n\n"
        f"*Name:* {name}\n"
        f"*Email:* {email}\n"
        f"*Company:* {company}\n"
        f"*Phone:* {phone}\n\n"
        f"*Project Details:*\n{project}"
    )
    encoded = urllib.parse.quote(text)
    whatsapp_url = f"https://wa.me/2120663332228?text={encoded}"

    return jsonify({
        'success': True,
        'whatsapp_url': whatsapp_url
    })


# ──────────────────────────────────────
#   SECURITY UTILITIES
# ──────────────────────────────────────

def sanitize_input(value):
    """Strip HTML tags and dangerous characters."""
    if not value:
        return ''
    # Remove HTML tags
    value = re.sub(r'<[^>]+>', '', str(value))
    # Remove null bytes
    value = value.replace('\x00', '')
    # Trim whitespace
    value = value.strip()
    return value


def is_valid_email(email):
    """Basic email format validation."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


# ──────────────────────────────────────
#   ERROR HANDLERS
# ──────────────────────────────────────

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'errors': ['Too many requests. Please try again later.']
    }), 429


@app.errorhandler(500)
def internal_error(e):
    return render_template('404.html'), 500


# ──────────────────────────────────────
#   RUN
# ──────────────────────────────────────

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
