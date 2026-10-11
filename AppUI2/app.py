"""
GC2-Sheet Web UI — Flask entry point.

Wires all blueprints together and starts the server.
Run: python app.py
"""
from flask import Flask, render_template
from flask_cors import CORS

from constants import CONFIG_DIR, DATA_DIR, ensure_dirs
import database as db
from routes import ALL_BLUEPRINTS


def create_app() -> Flask:
    ensure_dirs()
    db.init_db()

    app = Flask(__name__)
    CORS(app)

    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    print(f"\n  GC2-Sheet Web UI v4  ·  http://127.0.0.1:5000")
    print(f"  Config: {CONFIG_DIR}")
    print(f"  Data:   {DATA_DIR}\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
