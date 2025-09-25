package sqlinjection

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// SQLInjection MySQL SQL Injection Vulnerability Module
type SQLInjection struct {
	db *sql.DB
}

// Response 표준 응답 구조체
type Response map[string]interface{}

// NewSQLInjection 새로운 SQL Injection 인스턴스 생성
func NewSQLInjection() (*SQLInjection, error) {
	si := &SQLInjection{}
	if err := si.initializeDatabase(); err != nil {
		return nil, err
	}
	return si, nil
}

// 데이터베이스 연결 초기화
func (si *SQLInjection) initializeDatabase() error {
	// MySQL 연결 정보
	host := getEnv("MYSQL_HOST", "websec-mysql")
	port := getEnv("MYSQL_PORT", "3306")
	database := getEnv("MYSQL_DATABASE", "websec_test")
	username := getEnv("MYSQL_USER", "websec_user")
	password := getEnv("MYSQL_PASSWORD", "websec_password")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", username, password, host, port, database)

	var err error
	si.db, err = sql.Open("mysql", dsn)
	if err != nil {
		return err
	}

	// 연결 테스트
	if err = si.db.Ping(); err != nil {
		return err
	}

	// 테스트 데이터 초기화
	return si.initializeTestData()
}

// ExecuteVulnerableCode 취약한 코드 실행 (실제 SQL 인젝션 허용)
func (si *SQLInjection) ExecuteVulnerableCode(payload string, parameters map[string]string) Response {
	testType := getParam(parameters, "test_type", "login")
	target := getParam(parameters, "target", "username")

	switch testType {
	case "login":
		return si.vulnerableLogin(payload, target, parameters)
	case "search":
		return si.vulnerableSearch(payload)
	case "union":
		return si.vulnerableUnionSelect(payload)
	case "blind":
		return si.vulnerableBlindInjection(payload)
	case "time":
		return si.vulnerableTimeBasedInjection(payload)
	default:
		return si.vulnerableLogin(payload, target, parameters)
	}
}

// ExecuteSafeCode 안전한 코드 실행 (SQL 인젝션 방지)
func (si *SQLInjection) ExecuteSafeCode(payload string, parameters map[string]string) Response {
	testType := getParam(parameters, "test_type", "login")
	target := getParam(parameters, "target", "username")

	switch testType {
	case "login":
		return si.safeLogin(payload, target, parameters)
	case "search":
		return si.safeSearch(payload)
	case "union":
		return si.safeUnionSelect(payload)
	case "blind":
		return si.safeBlindInjection(payload)
	case "time":
		return si.safeTimeBasedInjection(payload)
	default:
		return si.safeLogin(payload, target, parameters)
	}
}

// 취약한 로그인 함수 (인젝션 허용)
func (si *SQLInjection) vulnerableLogin(payload, target string, parameters map[string]string) Response {
	// PayloadsAllTheThings 기반 MySQL 페이로드들
	testPayloads := []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' OR '1'='1' /*",
		"admin'--",
		"admin' #",
		"' OR 1=1--",
		"' UNION SELECT version(), user(), database() --",
		"'; SELECT SLEEP(5) --",
	}

	var username, password string
	if target == "username" {
		username = payload
		password = getParam(parameters, "password", "password")
	} else {
		username = getParam(parameters, "username", "admin")
		password = payload
	}

	// 취약한 쿼리 (직접 문자열 삽입)
	query := fmt.Sprintf("SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'", username, password)

	rows, err := si.db.Query(query)
	if err != nil {
		return Response{
			"success":           false,
			"vulnerable_query":  query,
			"sql_error":         err.Error(),
			"payload_injected":  payload,
			"educational_note":  "MySQL syntax error - indicates successful injection of malformed SQL",
			"security_impact":   "CRITICAL - SQL injection vulnerability confirmed",
		}
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, role string
		if err := rows.Scan(&id, &username, &role); err != nil {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":       id,
			"username": username,
			"role":     role,
		})
	}

	return Response{
		"success":                 true,
		"vulnerable_query":        query,
		"payload_injected":        payload,
		"results_count":           len(users),
		"data":                    users,
		"authentication_bypassed": len(users) > 0,
		"educational_analysis": map[string]interface{}{
			"vulnerability_type": "SQL Injection - Authentication Bypass",
			"attack_vector":      "Direct string concatenation in SQL query",
			"impact":             "Unauthorized access to user accounts",
			"example_payloads":   testPayloads,
			"database_type":      "MySQL",
		},
		"security_impact": func() string {
			if len(users) > 0 {
				return "HIGH - Authentication bypassed!"
			}
			return "Injection attempted but no data returned"
		}(),
	}
}

// 안전한 로그인 함수 (파라미터화된 쿼리)
func (si *SQLInjection) safeLogin(payload, target string, parameters map[string]string) Response {
	var username, password string
	if target == "username" {
		username = payload
		password = getParam(parameters, "password", "password")
	} else {
		username = getParam(parameters, "username", "admin")
		password = payload
	}

	// 안전한 쿼리 (파라미터화된 쿼리)
	query := "SELECT id, username, role FROM users WHERE username = ? AND password = ?"

	rows, err := si.db.Query(query, username, password)
	if err != nil {
		return Response{
			"success":           false,
			"safe_query":        query,
			"error":             "Database error (not SQL injection)",
			"educational_note":  "Legitimate database errors can still occur with safe queries",
		}
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, role string
		if err := rows.Scan(&id, &username, &role); err != nil {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":       id,
			"username": username,
			"role":     role,
		})
	}

	return Response{
		"success":                 true,
		"safe_query":              query,
		"parameters":              []string{username, password},
		"results_count":           len(users),
		"data":                    users,
		"authentication_bypassed": false,
		"educational_analysis": map[string]interface{}{
			"protection_method": "Parameterized Query (Prepared Statement)",
			"why_safe":          "User input is treated as data, not SQL code",
			"security_benefit":  "SQL injection is impossible with proper parameterization",
			"database_type":     "MySQL",
		},
		"security_impact": "NONE - Properly protected against SQL injection",
	}
}

// 취약한 검색 함수 (UNION 인젝션 허용)
func (si *SQLInjection) vulnerableSearch(payload string) Response {
	unionPayloads := []string{
		"' UNION SELECT version(), user(), database() --",
		"' UNION SELECT table_name, column_name, data_type FROM information_schema.columns --",
		"' UNION SELECT username, password, role FROM users --",
		"'; SELECT SLEEP(5) --",
	}

	query := fmt.Sprintf("SELECT id, title, content FROM articles WHERE title LIKE '%%%s%%'", payload)

	rows, err := si.db.Query(query)
	if err != nil {
		return Response{
			"success":           false,
			"vulnerable_query":  query,
			"sql_error":         err.Error(),
			"payload_injected":  payload,
			"educational_note":  "UNION injection syntax error - vulnerability confirmed",
		}
	}
	defer rows.Close()

	var articles []map[string]interface{}
	for rows.Next() {
		var id int
		var title, content string
		if err := rows.Scan(&id, &title, &content); err != nil {
			continue
		}
		articles = append(articles, map[string]interface{}{
			"id":      id,
			"title":   title,
			"content": content,
		})
	}

	return Response{
		"success":          true,
		"vulnerable_query": query,
		"payload_injected": payload,
		"results_count":    len(articles),
		"data":             articles,
		"educational_analysis": map[string]interface{}{
			"vulnerability_type":       "SQL Injection - UNION Attack",
			"attack_vector":            "UNION SELECT to extract additional data",
			"potential_data_exposure":  "Database schema, user credentials, sensitive data",
			"example_payloads":         unionPayloads,
			"database_type":            "MySQL",
		},
		"security_impact": func() string {
			if len(articles) > 3 {
				return "HIGH - Potential data extraction via UNION"
			}
			return "Search executed with injection point"
		}(),
	}
}

// 안전한 검색 함수
func (si *SQLInjection) safeSearch(payload string) Response {
	query := "SELECT id, title, content FROM articles WHERE title LIKE ?"

	rows, err := si.db.Query(query, "%"+payload+"%")
	if err != nil {
		return Response{
			"success":    false,
			"safe_query": query,
			"error":      "Database error (not SQL injection)",
		}
	}
	defer rows.Close()

	var articles []map[string]interface{}
	for rows.Next() {
		var id int
		var title, content string
		if err := rows.Scan(&id, &title, &content); err != nil {
			continue
		}
		articles = append(articles, map[string]interface{}{
			"id":      id,
			"title":   title,
			"content": content,
		})
	}

	return Response{
		"success":       true,
		"safe_query":    query,
		"search_term":   payload,
		"results_count": len(articles),
		"data":          articles,
		"educational_analysis": map[string]interface{}{
			"protection_method":     "Parameterized Search Query",
			"why_safe":              "Search term treated as literal string, not SQL code",
			"additional_protection": "Input validation can provide extra security layer",
			"database_type":         "MySQL",
		},
		"security_impact": "NONE - Protected against UNION injection attacks",
	}
}

// Blind SQL Injection (취약한 버전)
func (si *SQLInjection) vulnerableBlindInjection(payload string) Response {
	query := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE id = %s", payload)

	var count int
	err := si.db.QueryRow(query).Scan(&count)
	if err != nil {
		return Response{
			"success":           false,
			"vulnerable_query":  query,
			"sql_error":         err.Error(),
			"educational_note":  "Blind injection syntax error reveals vulnerability",
		}
	}

	return Response{
		"success":          true,
		"vulnerable_query": query,
		"payload_injected": payload,
		"result":           count,
		"boolean_result":   count > 0,
		"educational_analysis": map[string]interface{}{
			"vulnerability_type": "Blind SQL Injection - Boolean Based",
			"attack_method":      "True/False responses reveal information",
			"example_payloads": []string{
				"1 AND 1=1",
				"1 AND 1=2",
				"1 AND (SELECT COUNT(*) FROM users) > 0",
				"1 AND SUBSTRING((SELECT username FROM users LIMIT 1), 1, 1) = 'a'",
			},
			"database_type": "MySQL",
		},
		"security_impact": "MEDIUM - Data can be extracted character by character",
	}
}

// 안전한 Blind 쿼리
func (si *SQLInjection) safeBlindInjection(payload string) Response {
	// 입력값 검증
	if _, err := strconv.Atoi(payload); err != nil {
		return Response{
			"success":           false,
			"error":             "Invalid input - numeric value required",
			"educational_note":  "Input validation prevents injection attempts",
		}
	}

	query := "SELECT COUNT(*) FROM users WHERE id = ?"

	var count int
	err := si.db.QueryRow(query, payload).Scan(&count)
	if err != nil {
		return Response{
			"success":    false,
			"safe_query": query,
			"error":      "Database error (not SQL injection)",
		}
	}

	return Response{
		"success":         true,
		"safe_query":      query,
		"validated_input": payload,
		"result":          count,
		"boolean_result":  count > 0,
		"educational_analysis": map[string]interface{}{
			"protection_method":   "Input Validation + Parameterized Query",
			"validation_applied":  "Numeric input validation",
			"why_safe":            "Invalid input rejected before reaching database",
			"database_type":       "MySQL",
		},
		"security_impact": "NONE - Protected against blind injection",
	}
}

// Time-based Blind SQL Injection (취약한 버전)
func (si *SQLInjection) vulnerableTimeBasedInjection(payload string) Response {
	startTime := time.Now()
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", payload)

	rows, err := si.db.Query(query)
	executionTime := time.Since(startTime).Seconds()

	if err != nil {
		return Response{
			"success":           false,
			"vulnerable_query":  query,
			"sql_error":         err.Error(),
			"execution_time":    executionTime,
			"educational_note":  "Time-based injection syntax error",
		}
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, password, role string
		if err := rows.Scan(&id, &username, &password, &role); err != nil {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":       id,
			"username": username,
			"role":     role,
		})
	}

	return Response{
		"success":          true,
		"vulnerable_query": query,
		"payload_injected": payload,
		"execution_time":   executionTime,
		"data":             users,
		"educational_analysis": map[string]interface{}{
			"vulnerability_type": "Time-based Blind SQL Injection",
			"attack_method":      "Database delays reveal information",
			"example_payloads": []string{
				"1; SELECT SLEEP(5)",
				"1 AND (SELECT SLEEP(5))",
				"1 AND IF(1=1, SLEEP(5), 0)",
				"1 AND (CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)",
			},
			"database_type": "MySQL",
		},
		"security_impact": func() string {
			if executionTime > 1.0 {
				return "HIGH - Time delay indicates injection success"
			}
			return "Injection attempted"
		}(),
	}
}

// 안전한 Time-based 쿼리
func (si *SQLInjection) safeTimeBasedInjection(payload string) Response {
	startTime := time.Now()

	// 입력값 검증
	if _, err := strconv.Atoi(payload); err != nil {
		executionTime := time.Since(startTime).Seconds()
		return Response{
			"success":           false,
			"error":             "Invalid input - numeric value required",
			"execution_time":    executionTime,
			"educational_note":  "Input validation prevents time-based attacks",
		}
	}

	query := "SELECT * FROM users WHERE id = ?"

	rows, err := si.db.Query(query, payload)
	executionTime := time.Since(startTime).Seconds()

	if err != nil {
		return Response{
			"success":        false,
			"safe_query":     query,
			"error":          "Database error (not SQL injection)",
			"execution_time": executionTime,
		}
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var username, password, role string
		if err := rows.Scan(&id, &username, &password, &role); err != nil {
			continue
		}
		users = append(users, map[string]interface{}{
			"id":       id,
			"username": username,
			"role":     role,
		})
	}

	return Response{
		"success":         true,
		"safe_query":      query,
		"validated_input": payload,
		"execution_time":  executionTime,
		"data":            users,
		"educational_analysis": map[string]interface{}{
			"protection_method":   "Parameterized Query with Input Validation",
			"timing_protection":   "Consistent execution time regardless of input",
			"why_safe":            "No SQL code injection possible",
			"database_type":       "MySQL",
		},
		"security_impact": "NONE - Protected against time-based injection",
	}
}

// 테스트 데이터 초기화
func (si *SQLInjection) initializeTestData() error {
	// 사용자 테이블 생성
	_, err := si.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(50) NOT NULL,
			password VARCHAR(255) NOT NULL,
			role VARCHAR(20) DEFAULT 'user'
		)
	`)
	if err != nil {
		return err
	}

	// 게시글 테이블 생성
	_, err = si.db.Exec(`
		CREATE TABLE IF NOT EXISTS articles (
			id INT AUTO_INCREMENT PRIMARY KEY,
			title VARCHAR(200) NOT NULL,
			content TEXT
		)
	`)
	if err != nil {
		return err
	}

	// 기존 데이터 삭제
	si.db.Exec("DELETE FROM users")
	si.db.Exec("DELETE FROM articles")

	// 테스트 사용자 데이터 삽입
	_, err = si.db.Exec(`
		INSERT INTO users (username, password, role) VALUES
		('admin', 'admin123', 'admin'),
		('user1', 'password1', 'user'),
		('user2', 'password2', 'user'),
		('test', 'test123', 'user')
	`)
	if err != nil {
		return err
	}

	// 테스트 게시글 데이터 삽입
	_, err = si.db.Exec(`
		INSERT INTO articles (title, content) VALUES
		('First Article', 'This is the first article content'),
		('Second Article', 'This is the second article content'),
		('Security Guide', 'How to prevent SQL injection attacks')
	`)

	return err
}

// Close 데이터베이스 연결 종료
func (si *SQLInjection) Close() error {
	if si.db != nil {
		return si.db.Close()
	}
	return nil
}

// 유틸리티 함수들
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getParam(params map[string]string, key, defaultValue string) string {
	if value, exists := params[key]; exists && value != "" {
		return value
	}
	return defaultValue
}

// 더미 함수들 (인터페이스 호환성을 위해)
func (si *SQLInjection) vulnerableUnionSelect(payload string) Response {
	return si.vulnerableSearch(payload)
}

func (si *SQLInjection) safeUnionSelect(payload string) Response {
	return si.safeSearch(payload)
}