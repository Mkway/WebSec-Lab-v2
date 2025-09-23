from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import html
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

# XSS Test Endpoints
@app.route('/xss/vulnerable', methods=['GET'])
def xss_vulnerable():
    user_input = request.args.get('input', '<script>alert("XSS")</script>')
    # 취약한 코드 - 직접 출력
    return f'<h1>User Input: {user_input}</h1>'

@app.route('/xss/safe', methods=['GET'])
def xss_safe():
    user_input = request.args.get('input', '<script>alert("XSS")</script>')
    # 안전한 코드 - HTML 이스케이프
    safe_input = html.escape(user_input)
    return f'<h1>User Input: {safe_input}</h1>'

@app.route('/vulnerabilities', methods=['GET', 'POST'])
def vulnerabilities():
    return jsonify({
        'message': 'WebSec-Lab Python Server',
        'available': ['GET /xss/vulnerable', 'GET /xss/safe']
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)