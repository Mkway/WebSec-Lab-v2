from flask import Flask, jsonify, request
from flask_cors import CORS
import os
from datetime import datetime

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'service': 'websec-python',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'WebSec-Lab Python Server',
        'version': '2.0.0',
        'endpoints': ['/health', '/vulnerabilities']
    })

@app.route('/vulnerabilities', methods=['GET', 'POST'])
def vulnerabilities():
    return jsonify({
        'message': 'Vulnerability endpoints coming soon',
        'available': []
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)