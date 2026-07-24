"""
examples/flask_demo.py
~~~~~~~~~~~~~~~~~~~~~~
Example demonstrating Flask integration with AI SOS.
"""

from flask import Flask, request
import aisos

app = Flask(__name__)

# Initialize AI SOS and attach to Flask app instance
security = aisos.init()
security.attach(app)


@app.route("/")
def index():
    return {"message": "Flask Protected by AI SOS"}


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return {"query": q}


if __name__ == "__main__":
    app.run(port=5000)
