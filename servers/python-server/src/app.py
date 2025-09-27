from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_restx import Api, Resource, fields
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

# Flask-RESTX API setup
api = Api(
    app,
    doc='/docs/',
    title='WebSec-Lab Python API',
    version='2.0.0',
    description='Python Web Security Testing Platform'
)

# Initialize vulnerability modules
sql_injection = SQLInjection()

# API Models
vulnerability_test_model = api.model('VulnerabilityTest', {
    'mode': fields.String(required=True, enum=['vulnerable', 'safe'], default='vulnerable'),
    'payload': fields.String(required=True),
    'parameters': fields.Raw()
})

api_response_model = api.model('ApiResponse', {
    'success': fields.Boolean,
    'data': fields.Raw,
    'metadata': fields.Raw
})

# Swagger documentation for additional endpoints
@app.route('/swagger.json')
def swagger_spec():
    return jsonify(api.__schema__)

@api.route('/health')
class HealthAPI(Resource):
    def get(self):
        """Health Check"""
        return {
            'status': 'healthy',
            'service': 'websec-python',
            'timestamp': datetime.now().isoformat()
        }

@api.route('/')
class HomeAPI(Resource):
    def get(self):
        """Server Information"""
        return {
            'message': 'WebSec-Lab Python Server',
            'version': '2.0.0',
            'endpoints': ['/health', '/vulnerabilities', '/docs', '/swagger.json']
        }

# XSS Test Endpoints using Flask-RESTX
@api.route('/vulnerabilities/xss')
class XSSAPI(Resource):
    @api.expect(vulnerability_test_model)
    @api.marshal_with(api_response_model)
    def post(self):
        """Execute XSS Vulnerability Test"""
        try:
            data = request.get_json()
            print(f"[DEBUG] Received data: {data}")
            payload = data.get('payload', '<script>alert("XSS")</script>')
            mode = data.get('mode', 'vulnerable')
            print(f"[DEBUG] Payload: {payload}, Mode: {mode}")

            if mode == 'vulnerable':
                # 취약한 코드 - 직접 출력
                result = f'<h1>User Input: {payload}</h1>'
                attack_success = '<script>' in payload or 'javascript:' in payload
            else:
                # 안전한 코드 - HTML 이스케이프
                safe_input = html.escape(payload)
                result = f'<h1>User Input: {safe_input}</h1>'
                attack_success = False

            return {
                'success': True,
                'data': {
                    'result': result,
                    'vulnerability_detected': attack_success,
                    'payload_used': payload,
                    'attack_success': attack_success,
                    'execution_time': '0.001s'
                },
                'metadata': {
                    'language': 'python',
                    'vulnerability_type': 'xss',
                    'mode': mode,
                    'timestamp': datetime.now().isoformat()
                }
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'metadata': {
                    'language': 'python',
                    'vulnerability_type': 'xss',
                    'mode': mode
                }
            }, 500

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

# 표준 엔드포인트 추가 (Dashboard 호환성)
@app.route('/vulnerabilities/sql-injection', methods=['POST'])
def sql_injection_standard():
    try:
        data = request.get_json()
        mode = data.get('mode', 'vulnerable')
        username = data.get('username', 'admin')
        password = data.get('password', 'test')

        if mode == 'vulnerable':
            result = sql_injection.execute_vulnerable_code(username, {
                'test_type': 'login',
                'target': 'username',
                'username': username,
                'password': password
            })
        else:
            result = sql_injection.execute_safe_code(username, {
                'test_type': 'login',
                'target': 'username',
                'username': username,
                'password': password
            })

        return jsonify({
            'success': True,
            'data': result,
            'metadata': {
                'language': 'python',
                'vulnerability_type': 'sql_injection',
                'mode': mode,
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
                'mode': mode
            }
        }), 500

@app.route('/vulnerabilities', methods=['GET', 'POST'])
def vulnerabilities():
    return jsonify({
        'message': 'WebSec-Lab Python Server',
        'available': [
            'POST /vulnerabilities/sql-injection',
            'POST /vulnerabilities/xss',
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