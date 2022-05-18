from app import app, db
from app.models import User, Post
import logging


if __name__ == "__main__":
    from waitress import serve
    logger = logging.getLogger('waitress')
    logger.setLevel(logging.INFO)
    serve(app, host="0.0.0.0", port=8090)