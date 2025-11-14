"""
WSGI entry point for the ISP Middleware application
"""

from app import create_app, celery

# Create the application instance
app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
