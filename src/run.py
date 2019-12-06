import logging

from app import app

log = logging.getLogger(__name__)
log.setLevel(level=logging.DEBUG)

if __name__ == "__main__":
    log.info("Starting APP")
    app.run(host="127.0.0.1", port="5000", debug=True)
