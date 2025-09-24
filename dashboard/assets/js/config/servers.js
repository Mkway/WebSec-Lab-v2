// 언어별 서버 설정
export const languageServers = {
    'PHP': {
        name: 'PHP',
        port: 8080,
        status: 'unknown',
        icon: '🐘',
        color: '#4F5B93',
        database: 'MySQL'
    },
    'Node.js': {
        name: 'Node.js',
        port: 3000,
        status: 'unknown',
        icon: '💚',
        color: '#68A063',
        database: 'MongoDB'
    },
    'Python': {
        name: 'Python',
        port: 5000,
        status: 'unknown',
        icon: '🐍',
        color: '#3776AB',
        database: 'PostgreSQL'
    },
    'Java': {
        name: 'Java',
        port: 8081,
        status: 'unknown',
        icon: '☕',
        color: '#ED8B00',
        database: 'H2'
    },
    'Go': {
        name: 'Go',
        port: 8082,
        status: 'unknown',
        icon: '🐹',
        color: '#00ADD8',
        database: 'MySQL'
    }
};

// 취약점 카테고리 설정
export const vulnerabilityCategories = [
    {
        id: 'injection-attacks',
        name: '💉 Injection Attacks',
        priority: 'high',
        icon: 'fas fa-syringe',
        description: '코드/쿼리 주입 공격',
        vulnerabilities: [
            { type: 'sql-injection', name: 'SQL Injection', icon: 'fas fa-database', status: 'completed', progress: 100, languages: ['PHP', 'Node.js', 'Python', 'Java', 'Go'] },
            { type: 'xss', name: 'XSS', icon: 'fas fa-code', status: 'completed', progress: 100, languages: ['PHP', 'Node.js', 'Python', 'Java', 'Go'] },
            { type: 'command-injection', name: 'Command Injection', icon: 'fas fa-terminal', status: 'planned', progress: 0, languages: [] },
            { type: 'nosql-injection', name: 'NoSQL Injection', icon: 'fas fa-leaf', status: 'planned', progress: 0, languages: [] }
        ]
    },
    {
        id: 'file-system-attacks',
        name: '📁 File System Attacks',
        priority: 'high',
        icon: 'fas fa-folder-open',
        description: '파일 시스템 공격',
        vulnerabilities: [
            { type: 'file-upload', name: 'File Upload', icon: 'fas fa-upload', status: 'planned', progress: 0, languages: [] },
            { type: 'directory-traversal', name: 'Path Traversal', icon: 'fas fa-route', status: 'planned', progress: 0, languages: [] },
            { type: 'file-inclusion', name: 'File Inclusion', icon: 'fas fa-file-import', status: 'planned', progress: 0, languages: [] }
        ]
    },
    {
        id: 'web-security-bypass',
        name: '🌐 Web Security Bypass',
        priority: 'medium',
        icon: 'fas fa-shield-alt',
        description: '웹 보안 메커니즘 우회',
        vulnerabilities: [
            { type: 'csrf', name: 'CSRF', icon: 'fas fa-exchange-alt', status: 'planned', progress: 0, languages: [] },
            { type: 'ssti', name: 'SSTI', icon: 'fas fa-code-branch', status: 'planned', progress: 0, languages: [] },
            { type: 'xxe', name: 'XXE', icon: 'fas fa-file-code', status: 'planned', progress: 0, languages: [] },
            { type: 'ssrf', name: 'SSRF', icon: 'fas fa-network-wired', status: 'planned', progress: 0, languages: [] }
        ]
    },
    {
        id: 'advanced-attacks',
        name: '🔓 Advanced Attacks',
        priority: 'low',
        icon: 'fas fa-lock-open',
        description: '고급 공격 기법',
        vulnerabilities: [
            { type: 'deserialization', name: 'Insecure Deserialization', icon: 'fas fa-unlink', status: 'planned', progress: 0, languages: [] },
            { type: 'ldap-injection', name: 'LDAP Injection', icon: 'fas fa-building', status: 'planned', progress: 0, languages: [] },
            { type: 'xpath-injection', name: 'XPath Injection', icon: 'fas fa-sitemap', status: 'planned', progress: 0, languages: [] }
        ]
    }
];