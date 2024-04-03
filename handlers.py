from flask import Flask, jsonify
app = Flask(__name__)
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    print(error)
    return jsonify({'error': 'Forbidden'}, ), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404
