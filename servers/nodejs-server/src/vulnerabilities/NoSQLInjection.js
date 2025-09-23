const { MongoClient } = require('mongodb');

/**
 * NoSQL Injection Vulnerability Module for MongoDB
 * PayloadsAllTheThings 기반의 실제 NoSQL 인젝션 테스트
 */
class NoSQLInjection {
    constructor() {
        this.mongoUrl = process.env.MONGODB_URL || 'mongodb://websec-mongodb:27017';
        this.dbName = process.env.MONGODB_DATABASE || 'websec_test';
        this.client = null;
        this.db = null;
        this.initializeTestData();
    }

    /**
     * MongoDB 연결 초기화
     */
    async connect() {
        if (!this.client) {
            this.client = new MongoClient(this.mongoUrl);
            await this.client.connect();
            this.db = this.client.db(this.dbName);
        }
        return this.db;
    }

    /**
     * 취약한 코드 실행 (실제 NoSQL 인젝션 허용)
     */
    async executeVulnerableCode(payload, parameters = {}) {
        const testType = parameters.test_type || 'login';
        const target = parameters.target || 'username';

        try {
            await this.connect();

            switch (testType) {
                case 'login':
                    return await this.vulnerableLogin(payload, target, parameters);
                case 'search':
                    return await this.vulnerableSearch(payload);
                case 'where':
                    return await this.vulnerableWhereInjection(payload);
                case 'regex':
                    return await this.vulnerableRegexInjection(payload);
                default:
                    return await this.vulnerableLogin(payload, target, parameters);
            }
        } catch (error) {
            return {
                success: false,
                error: error.message,
                payload_executed: true,
                injection_detected: true,
                educational_note: 'NoSQL error occurred - indicates potential injection vulnerability'
            };
        }
    }

    /**
     * 안전한 코드 실행 (NoSQL 인젝션 방지)
     */
    async executeSafeCode(payload, parameters = {}) {
        const testType = parameters.test_type || 'login';
        const target = parameters.target || 'username';

        try {
            await this.connect();

            switch (testType) {
                case 'login':
                    return await this.safeLogin(payload, target, parameters);
                case 'search':
                    return await this.safeSearch(payload);
                case 'where':
                    return await this.safeWhereQuery(payload);
                case 'regex':
                    return await this.safeRegexQuery(payload);
                default:
                    return await this.safeLogin(payload, target, parameters);
            }
        } catch (error) {
            return {
                success: false,
                error: 'Safe code execution failed',
                payload_executed: false,
                educational_note: 'Proper input validation prevents NoSQL injection'
            };
        }
    }

    /**
     * 취약한 로그인 함수 (NoSQL 인젝션 허용)
     */
    async vulnerableLogin(payload, target, parameters) {
        // PayloadsAllTheThings 기반 NoSQL 페이로드들
        const testPayloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$or": [{"username": {"$ne": null}}, {"password": {"$ne": null}}]}'
        ];

        let query = {};

        if (target === 'username') {
            // 취약한 방식: JSON 파싱을 통한 직접 삽입
            try {
                query.username = JSON.parse(payload);
            } catch {
                query.username = payload;
            }
            query.password = parameters.password || 'password';
        } else {
            query.username = parameters.username || 'admin';
            try {
                query.password = JSON.parse(payload);
            } catch {
                query.password = payload;
            }
        }

        try {
            const users = await this.db.collection('users').find(query).toArray();

            return {
                success: true,
                vulnerable_query: JSON.stringify(query),
                payload_injected: payload,
                results_count: users.length,
                data: users.map(u => ({ id: u._id, username: u.username, role: u.role })),
                authentication_bypassed: users.length > 0,
                educational_analysis: {
                    vulnerability_type: 'NoSQL Injection - Authentication Bypass',
                    attack_vector: 'Direct JSON parsing without validation',
                    impact: 'Unauthorized access to user accounts',
                    example_payloads: testPayloads
                },
                security_impact: users.length > 0 ? 'HIGH - Authentication bypassed!' : 'Injection attempted but no data returned'
            };
        } catch (error) {
            return {
                success: false,
                vulnerable_query: JSON.stringify(query),
                nosql_error: error.message,
                payload_injected: payload,
                educational_note: 'NoSQL error - indicates successful injection attempt',
                security_impact: 'CRITICAL - NoSQL injection vulnerability confirmed'
            };
        }
    }

    /**
     * 안전한 로그인 함수 (입력 검증 적용)
     */
    async safeLogin(payload, target, parameters) {
        // 입력 검증 및 타입 확인
        const validateInput = (input) => {
            if (typeof input !== 'string') return false;
            if (input.includes('{') || input.includes('}')) return false;
            if (input.includes('$')) return false;
            return true;
        };

        let username, password;

        if (target === 'username') {
            if (!validateInput(payload)) {
                return {
                    success: false,
                    error: 'Invalid username format',
                    educational_note: 'Input validation prevents injection attempts'
                };
            }
            username = payload;
            password = parameters.password || 'password';
        } else {
            username = parameters.username || 'admin';
            if (!validateInput(payload)) {
                return {
                    success: false,
                    error: 'Invalid password format',
                    educational_note: 'Input validation prevents injection attempts'
                };
            }
            password = payload;
        }

        const query = { username, password };

        try {
            const users = await this.db.collection('users').find(query).toArray();

            return {
                success: true,
                safe_query: JSON.stringify(query),
                validated_input: { username, password },
                results_count: users.length,
                data: users.map(u => ({ id: u._id, username: u.username, role: u.role })),
                authentication_bypassed: false,
                educational_analysis: {
                    protection_method: 'Input Validation and Type Checking',
                    why_safe: 'User input is validated before database query',
                    security_benefit: 'NoSQL injection is impossible with proper validation'
                },
                security_impact: 'NONE - Properly protected against NoSQL injection'
            };
        } catch (error) {
            return {
                success: false,
                safe_query: JSON.stringify(query),
                error: 'Database error (not NoSQL injection)',
                educational_note: 'Legitimate database errors can still occur with safe queries'
            };
        }
    }

    /**
     * 취약한 검색 함수 ($where 인젝션 허용)
     */
    async vulnerableSearch(payload) {
        const wherePayloads = [
            'function() { return true; }',
            'function() { return this.username == "admin"; }',
            'function() { return /.*/.test(this.username); }',
            'function() { sleep(5000); return true; }'
        ];

        let query = {};

        try {
            // 취약한 방식: $where 쿼리에 직접 삽입
            query.$where = payload;
        } catch {
            query.title = new RegExp(payload, 'i');
        }

        try {
            const articles = await this.db.collection('articles').find(query).toArray();

            return {
                success: true,
                vulnerable_query: JSON.stringify(query),
                payload_injected: payload,
                results_count: articles.length,
                data: articles,
                educational_analysis: {
                    vulnerability_type: 'NoSQL Injection - $where Attack',
                    attack_vector: '$where clause allows JavaScript code execution',
                    potential_impact: 'Server-side JavaScript execution, data extraction, DoS',
                    example_payloads: wherePayloads
                },
                security_impact: articles.length > 0 ? 'HIGH - Potential code execution via $where' : 'Query executed with injection point'
            };
        } catch (error) {
            return {
                success: false,
                vulnerable_query: JSON.stringify(query),
                nosql_error: error.message,
                payload_injected: payload,
                educational_note: '$where injection error - vulnerability confirmed'
            };
        }
    }

    /**
     * 안전한 검색 함수
     */
    async safeSearch(payload) {
        // $where 사용 금지, 정규식만 허용
        const query = {
            title: new RegExp(payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
        };

        try {
            const articles = await this.db.collection('articles').find(query).toArray();

            return {
                success: true,
                safe_query: JSON.stringify(query),
                search_term: payload,
                results_count: articles.length,
                data: articles,
                educational_analysis: {
                    protection_method: 'Escaped Regex Query (no $where)',
                    why_safe: 'Special characters escaped, no code execution possible',
                    additional_protection: 'Input length limits and character filtering'
                },
                security_impact: 'NONE - Protected against $where injection attacks'
            };
        } catch (error) {
            return {
                success: false,
                safe_query: JSON.stringify(query),
                error: 'Database error (not NoSQL injection)'
            };
        }
    }

    /**
     * 취약한 regex 인젝션
     */
    async vulnerableRegexInjection(payload) {
        try {
            const query = {
                username: { $regex: payload }
            };

            const users = await this.db.collection('users').find(query).toArray();

            return {
                success: true,
                vulnerable_query: JSON.stringify(query),
                payload_injected: payload,
                results_count: users.length,
                data: users.map(u => ({ id: u._id, username: u.username, role: u.role })),
                educational_analysis: {
                    vulnerability_type: 'NoSQL Injection - Regex Attack',
                    attack_vector: 'Unescaped regex patterns in $regex operator',
                    potential_impact: 'ReDoS (Regular Expression Denial of Service), data extraction',
                    example_payloads: ['.*', '^admin', '(.*)*', '(?=(.*)*)*']
                }
            };
        } catch (error) {
            return {
                success: false,
                error: error.message,
                educational_note: 'Regex injection error - vulnerability confirmed'
            };
        }
    }

    /**
     * 안전한 regex 쿼리
     */
    async safeRegexQuery(payload) {
        // 입력 검증 및 이스케이프
        const escapedPayload = payload.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const query = {
            username: { $regex: escapedPayload, $options: 'i' }
        };

        try {
            const users = await this.db.collection('users').find(query).toArray();

            return {
                success: true,
                safe_query: JSON.stringify(query),
                escaped_input: escapedPayload,
                results_count: users.length,
                data: users.map(u => ({ id: u._id, username: u.username, role: u.role })),
                educational_analysis: {
                    protection_method: 'Regex Escaping and Input Validation',
                    why_safe: 'Special regex characters escaped before query',
                    security_benefit: 'Prevents ReDoS and injection attacks'
                },
                security_impact: 'NONE - Protected against regex injection'
            };
        } catch (error) {
            return {
                success: false,
                safe_query: JSON.stringify(query),
                error: 'Database error (not NoSQL injection)'
            };
        }
    }

    /**
     * 테스트 데이터 초기화
     */
    async initializeTestData() {
        try {
            await this.connect();

            // 사용자 컬렉션 초기화
            const usersCollection = this.db.collection('users');
            await usersCollection.deleteMany({});
            await usersCollection.insertMany([
                { username: 'admin', password: 'admin123', role: 'admin' },
                { username: 'user1', password: 'password1', role: 'user' },
                { username: 'user2', password: 'password2', role: 'user' },
                { username: 'test', password: 'test123', role: 'user' }
            ]);

            // 게시글 컬렉션 초기화
            const articlesCollection = this.db.collection('articles');
            await articlesCollection.deleteMany({});
            await articlesCollection.insertMany([
                { title: 'First Article', content: 'This is the first article content' },
                { title: 'Second Article', content: 'This is the second article content' },
                { title: 'Security Guide', content: 'How to prevent NoSQL injection attacks' }
            ]);

        } catch (error) {
            console.error('Failed to initialize NoSQL injection test data:', error.message);
        }
    }

    /**
     * 연결 종료
     */
    async close() {
        if (this.client) {
            await this.client.close();
            this.client = null;
            this.db = null;
        }
    }
}

module.exports = NoSQLInjection;