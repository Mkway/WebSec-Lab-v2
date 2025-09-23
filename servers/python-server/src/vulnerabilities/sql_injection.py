import psycopg2
import psycopg2.extras
import os
import time
import re
from datetime import datetime

class SQLInjection:
    """
    PostgreSQL SQL Injection Vulnerability Module
    PayloadsAllTheThings 기반의 실제 SQL 인젝션 테스트
    """

    def __init__(self):
        self.db_config = {
            'host': os.environ.get('POSTGRES_HOST', 'websec-postgres'),
            'port': os.environ.get('POSTGRES_PORT', 5432),
            'database': os.environ.get('POSTGRES_DATABASE', 'websec_test'),
            'user': os.environ.get('POSTGRES_USER', 'websec_user'),
            'password': os.environ.get('POSTGRES_PASSWORD', 'websec_password')
        }
        self.connection = None
        self.initialize_test_data()

    def get_connection(self):
        """PostgreSQL 연결 생성"""
        if not self.connection or self.connection.closed:
            self.connection = psycopg2.connect(**self.db_config)
        return self.connection

    def execute_vulnerable_code(self, payload, parameters=None):
        """취약한 코드 실행 (실제 SQL 인젝션 허용)"""
        if parameters is None:
            parameters = {}

        test_type = parameters.get('test_type', 'login')
        target = parameters.get('target', 'username')

        try:
            if test_type == 'login':
                return self.vulnerable_login(payload, target, parameters)
            elif test_type == 'search':
                return self.vulnerable_search(payload)
            elif test_type == 'union':
                return self.vulnerable_union_select(payload)
            elif test_type == 'blind':
                return self.vulnerable_blind_injection(payload)
            elif test_type == 'time':
                return self.vulnerable_time_based_injection(payload)
            else:
                return self.vulnerable_login(payload, target, parameters)
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'payload_executed': True,
                'sql_error': True,
                'educational_note': 'SQL error occurred - indicates potential injection vulnerability'
            }

    def execute_safe_code(self, payload, parameters=None):
        """안전한 코드 실행 (SQL 인젝션 방지)"""
        if parameters is None:
            parameters = {}

        test_type = parameters.get('test_type', 'login')
        target = parameters.get('target', 'username')

        try:
            if test_type == 'login':
                return self.safe_login(payload, target, parameters)
            elif test_type == 'search':
                return self.safe_search(payload)
            elif test_type == 'union':
                return self.safe_union_select(payload)
            elif test_type == 'blind':
                return self.safe_blind_injection(payload)
            elif test_type == 'time':
                return self.safe_time_based_injection(payload)
            else:
                return self.safe_login(payload, target, parameters)
        except Exception as e:
            return {
                'success': False,
                'error': 'Safe code execution failed',
                'payload_executed': False,
                'educational_note': 'Parameterized queries prevent SQL injection'
            }

    def vulnerable_login(self, payload, target, parameters):
        """취약한 로그인 함수 (인젝션 허용)"""
        # PayloadsAllTheThings 기반 PostgreSQL 페이로드들
        test_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "' OR 1=1--",
            "' UNION SELECT version(), current_user --",
            "'; SELECT pg_sleep(5) --"
        ]

        if target == 'username':
            username = payload
            password = parameters.get('password', 'password')
        else:
            username = parameters.get('username', 'admin')
            password = payload

        # 취약한 쿼리 (직접 문자열 삽입)
        sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"

        try:
            conn = self.get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                users = cur.fetchall()

            # 딕셔너리로 변환
            users_list = [dict(user) for user in users]

            return {
                'success': True,
                'vulnerable_query': sql,
                'payload_injected': payload,
                'results_count': len(users_list),
                'data': users_list,
                'authentication_bypassed': len(users_list) > 0,
                'educational_analysis': {
                    'vulnerability_type': 'SQL Injection - Authentication Bypass',
                    'attack_vector': 'Direct string concatenation in SQL query',
                    'impact': 'Unauthorized access to user accounts',
                    'example_payloads': test_payloads,
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'HIGH - Authentication bypassed!' if len(users_list) > 0 else 'Injection attempted but no data returned'
            }
        except psycopg2.Error as e:
            return {
                'success': False,
                'vulnerable_query': sql,
                'sql_error': str(e),
                'payload_injected': payload,
                'educational_note': 'PostgreSQL syntax error - indicates successful injection of malformed SQL',
                'security_impact': 'CRITICAL - SQL injection vulnerability confirmed'
            }

    def safe_login(self, payload, target, parameters):
        """안전한 로그인 함수 (파라미터화된 쿼리)"""
        if target == 'username':
            username = payload
            password = parameters.get('password', 'password')
        else:
            username = parameters.get('username', 'admin')
            password = payload

        # 안전한 쿼리 (파라미터화된 쿼리)
        sql = "SELECT id, username, role FROM users WHERE username = %s AND password = %s"

        try:
            conn = self.get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (username, password))
                users = cur.fetchall()

            users_list = [dict(user) for user in users]

            return {
                'success': True,
                'safe_query': sql,
                'parameters': [username, password],
                'results_count': len(users_list),
                'data': users_list,
                'authentication_bypassed': False,
                'educational_analysis': {
                    'protection_method': 'Parameterized Query (Prepared Statement)',
                    'why_safe': 'User input is treated as data, not SQL code',
                    'security_benefit': 'SQL injection is impossible with proper parameterization',
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'NONE - Properly protected against SQL injection'
            }
        except psycopg2.Error as e:
            return {
                'success': False,
                'safe_query': sql,
                'error': 'Database error (not SQL injection)',
                'educational_note': 'Legitimate database errors can still occur with safe queries'
            }

    def vulnerable_search(self, payload):
        """취약한 검색 함수 (UNION 인젝션 허용)"""
        union_payloads = [
            "' UNION SELECT version(), current_user, current_database() --",
            "' UNION SELECT table_name, column_name, data_type FROM information_schema.columns --",
            "' UNION SELECT username, password, role FROM users --",
            "'; SELECT pg_sleep(5) --"
        ]

        sql = f"SELECT id, title, content FROM articles WHERE title ILIKE '%{payload}%'"

        try:
            conn = self.get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                articles = cur.fetchall()

            articles_list = [dict(article) for article in articles]

            return {
                'success': True,
                'vulnerable_query': sql,
                'payload_injected': payload,
                'results_count': len(articles_list),
                'data': articles_list,
                'educational_analysis': {
                    'vulnerability_type': 'SQL Injection - UNION Attack',
                    'attack_vector': 'UNION SELECT to extract additional data',
                    'potential_data_exposure': 'Database schema, user credentials, sensitive data',
                    'example_payloads': union_payloads,
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'HIGH - Potential data extraction via UNION' if len(articles_list) > 3 else 'Search executed with injection point'
            }
        except psycopg2.Error as e:
            return {
                'success': False,
                'vulnerable_query': sql,
                'sql_error': str(e),
                'payload_injected': payload,
                'educational_note': 'UNION injection syntax error - vulnerability confirmed'
            }

    def safe_search(self, payload):
        """안전한 검색 함수"""
        sql = "SELECT id, title, content FROM articles WHERE title ILIKE %s"

        try:
            conn = self.get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (f'%{payload}%',))
                articles = cur.fetchall()

            articles_list = [dict(article) for article in articles]

            return {
                'success': True,
                'safe_query': sql,
                'search_term': payload,
                'results_count': len(articles_list),
                'data': articles_list,
                'educational_analysis': {
                    'protection_method': 'Parameterized Search Query',
                    'why_safe': 'Search term treated as literal string, not SQL code',
                    'additional_protection': 'Input validation can provide extra security layer',
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'NONE - Protected against UNION injection attacks'
            }
        except psycopg2.Error as e:
            return {
                'success': False,
                'safe_query': sql,
                'error': 'Database error (not SQL injection)'
            }

    def vulnerable_blind_injection(self, payload):
        """Blind SQL Injection (취약한 버전)"""
        sql = f"SELECT COUNT(*) FROM users WHERE id = {payload}"

        try:
            conn = self.get_connection()
            with conn.cursor() as cur:
                cur.execute(sql)
                count = cur.fetchone()[0]

            return {
                'success': True,
                'vulnerable_query': sql,
                'payload_injected': payload,
                'result': count,
                'boolean_result': count > 0,
                'educational_analysis': {
                    'vulnerability_type': 'Blind SQL Injection - Boolean Based',
                    'attack_method': 'True/False responses reveal information',
                    'example_payloads': [
                        "1 AND 1=1",
                        "1 AND 1=2",
                        "1 AND (SELECT COUNT(*) FROM users) > 0",
                        "1 AND SUBSTRING((SELECT username FROM users LIMIT 1), 1, 1) = 'a'"
                    ],
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'MEDIUM - Data can be extracted character by character'
            }
        except psycopg2.Error as e:
            return {
                'success': False,
                'vulnerable_query': sql,
                'sql_error': str(e),
                'educational_note': 'Blind injection syntax error reveals vulnerability'
            }

    def safe_blind_injection(self, payload):
        """안전한 Blind 쿼리"""
        sql = "SELECT COUNT(*) FROM users WHERE id = %s"

        try:
            # 입력값 검증
            if not payload.isdigit():
                return {
                    'success': False,
                    'error': 'Invalid input - numeric value required',
                    'educational_note': 'Input validation prevents injection attempts'
                }

            conn = self.get_connection()
            with conn.cursor() as cur:
                cur.execute(sql, (int(payload),))
                count = cur.fetchone()[0]

            return {
                'success': True,
                'safe_query': sql,
                'validated_input': payload,
                'result': count,
                'boolean_result': count > 0,
                'educational_analysis': {
                    'protection_method': 'Input Validation + Parameterized Query',
                    'validation_applied': 'Numeric input validation',
                    'why_safe': 'Invalid input rejected before reaching database',
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'NONE - Protected against blind injection'
            }
        except psycopg2.Error as e:
            return {
                'success': False,
                'safe_query': sql,
                'error': 'Database error (not SQL injection)'
            }

    def vulnerable_time_based_injection(self, payload):
        """Time-based Blind SQL Injection (취약한 버전)"""
        start_time = time.time()
        sql = f"SELECT * FROM users WHERE id = {payload}"

        try:
            conn = self.get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                data = cur.fetchall()

            execution_time = time.time() - start_time
            data_list = [dict(row) for row in data]

            return {
                'success': True,
                'vulnerable_query': sql,
                'payload_injected': payload,
                'execution_time': round(execution_time, 4),
                'data': data_list,
                'educational_analysis': {
                    'vulnerability_type': 'Time-based Blind SQL Injection',
                    'attack_method': 'Database delays reveal information',
                    'example_payloads': [
                        "1; SELECT pg_sleep(5)",
                        "1 AND (SELECT COUNT(*) FROM pg_sleep(5)) = 0",
                        "1; WAITFOR DELAY '00:00:05'",  # SQL Server 스타일 (참고용)
                        "1 AND (CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL"
                    ],
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'HIGH - Time delay indicates injection success' if execution_time > 1 else 'Injection attempted'
            }
        except psycopg2.Error as e:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'vulnerable_query': sql,
                'sql_error': str(e),
                'execution_time': round(execution_time, 4),
                'educational_note': 'Time-based injection syntax error'
            }

    def safe_time_based_injection(self, payload):
        """안전한 Time-based 쿼리"""
        start_time = time.time()
        sql = "SELECT * FROM users WHERE id = %s"

        try:
            if not payload.isdigit():
                return {
                    'success': False,
                    'error': 'Invalid input - numeric value required',
                    'execution_time': round(time.time() - start_time, 4),
                    'educational_note': 'Input validation prevents time-based attacks'
                }

            conn = self.get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (int(payload),))
                data = cur.fetchall()

            execution_time = time.time() - start_time
            data_list = [dict(row) for row in data]

            return {
                'success': True,
                'safe_query': sql,
                'validated_input': payload,
                'execution_time': round(execution_time, 4),
                'data': data_list,
                'educational_analysis': {
                    'protection_method': 'Parameterized Query with Input Validation',
                    'timing_protection': 'Consistent execution time regardless of input',
                    'why_safe': 'No SQL code injection possible',
                    'database_type': 'PostgreSQL'
                },
                'security_impact': 'NONE - Protected against time-based injection'
            }
        except psycopg2.Error as e:
            execution_time = time.time() - start_time
            return {
                'success': False,
                'safe_query': sql,
                'error': 'Database error (not SQL injection)',
                'execution_time': round(execution_time, 4)
            }

    def initialize_test_data(self):
        """테스트 데이터 초기화"""
        try:
            conn = self.get_connection()
            with conn.cursor() as cur:
                # 사용자 테이블 생성
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        role VARCHAR(20) DEFAULT 'user'
                    )
                """)

                # 게시글 테이블 생성
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS articles (
                        id SERIAL PRIMARY KEY,
                        title VARCHAR(200) NOT NULL,
                        content TEXT
                    )
                """)

                # 기존 데이터 삭제 후 테스트 데이터 삽입
                cur.execute("DELETE FROM users")
                cur.execute("DELETE FROM articles")

                # 테스트 사용자 데이터
                users_data = [
                    ('admin', 'admin123', 'admin'),
                    ('user1', 'password1', 'user'),
                    ('user2', 'password2', 'user'),
                    ('test', 'test123', 'user')
                ]

                cur.executemany(
                    "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                    users_data
                )

                # 테스트 게시글 데이터
                articles_data = [
                    ('First Article', 'This is the first article content'),
                    ('Second Article', 'This is the second article content'),
                    ('Security Guide', 'How to prevent SQL injection attacks')
                ]

                cur.executemany(
                    "INSERT INTO articles (title, content) VALUES (%s, %s)",
                    articles_data
                )

                conn.commit()

        except psycopg2.Error as e:
            print(f"Failed to initialize SQL injection test data: {e}")

    def close_connection(self):
        """연결 종료"""
        if self.connection and not self.connection.closed:
            self.connection.close()

    def __del__(self):
        """소멸자"""
        self.close_connection()