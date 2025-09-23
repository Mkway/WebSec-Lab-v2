from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import html
from datetime import datetime

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Import vulnerabilities
from vulnerabilities.sql_injection import SQLInjection

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')

# Initialize vulnerability modules
sql_injection = SQLInjection()

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

# SQL Injection Test Endpoints
@app.route('/sql/vulnerable/login', methods=['GET'])
def sql_vulnerable_login():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        payload = username or password or "' OR '1'='1' --"
        target = 'username' if username else 'password'

        result = sql_injection.execute_vulnerable_code(payload, {
            'test_type': 'login',
            'target': target,
            'username': username or 'admin',
            'password': password or 'password'
        })

        return jsonify({
            'success': True,
            'data': result,
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': 'vulnerable',
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': 'vulnerable'
            }
        }), 500

@app.route('/sql/safe/login', methods=['GET'])
def sql_safe_login():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        payload = username or password or 'admin'
        target = 'username' if username else 'password'

        result = sql_injection.execute_safe_code(payload, {
            'test_type': 'login',
            'target': target,
            'username': username or 'admin',
            'password': password or 'password'
        })

        return jsonify({
            'success': True,
            'data': result,
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': 'safe',
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': 'safe'
            }
        }), 500

@app.route('/sql/vulnerable/search', methods=['GET'])
def sql_vulnerable_search():
    try:
        query = request.args.get('query', "' UNION SELECT version(), current_user, current_database() --")

        result = sql_injection.execute_vulnerable_code(query, {
            'test_type': 'search'
        })

        return jsonify({
            'success': True,
            'data': result,
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': 'vulnerable',
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/sql/safe/search', methods=['GET'])
def sql_safe_search():
    try:
        query = request.args.get('query', 'article')

        result = sql_injection.execute_safe_code(query, {
            'test_type': 'search'
        })

        return jsonify({
            'success': True,
            'data': result,
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': 'safe',
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/vulnerabilities', methods=['GET', 'POST'])
def vulnerabilities():
    return jsonify({
        'message': 'WebSec-Lab Python Server',
        'available': [
            'GET /xss/vulnerable',
            'GET /xss/safe',
            'GET /sql/vulnerable/login',
            'GET /sql/safe/login',
            'GET /sql/vulnerable/search',
            'GET /sql/safe/search'
        ]
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug)