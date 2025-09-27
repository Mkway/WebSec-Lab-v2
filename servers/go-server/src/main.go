// @title WebSec-Lab Go API
// @version 2.0.0
// @description Go Web Security Testing Platform
// @host localhost:8082
// @BasePath /
package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/websec-lab/websec-lab-v2/go-server/sqlinjection"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Initialize SQL Injection service
	sqlInj, err := sqlinjection.NewSQLInjection()
	if err != nil {
		log.Printf("Failed to initialize SQL injection service: %v", err)
	}
	defer func() {
		if sqlInj != nil {
			sqlInj.Close()
		}
	}()

	// Set Gin mode
	if mode := os.Getenv("GIN_MODE"); mode != "" {
		gin.SetMode(mode)
	}

	r := gin.Default()

	// CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Swagger endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Routes
	// @Summary Health Check
	// @Description Check if the server is running and healthy
	// @Tags Health
	// @Produce json
	// @Success 200 {object} map[string]interface{}
	// @Router /health [get]
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"service":   "websec-go",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	// @Summary Server Information
	// @Description Get basic server information and available endpoints
	// @Tags Information
	// @Produce json
	// @Success 200 {object} map[string]interface{}
	// @Router / [get]
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":   "WebSec-Lab Go Server",
			"version":   "2.0.0",
			"endpoints": []string{"/health", "/swagger/index.html", "/xss/vulnerable", "/xss/safe", "/sql/vulnerable/login", "/sql/safe/login", "/sql/vulnerable/search", "/sql/safe/search"},
		})
	})

	// XSS Test Endpoints
	// @Summary XSS - Vulnerable Endpoint
	// @Description Vulnerable endpoint for Cross-Site Scripting (XSS) testing
	// @Tags XSS
	// @Param input query string false "Input to test XSS vulnerability"
	// @Produce html
	// @Success 200 {string} string "HTML response with unescaped input"
	// @Router /xss/vulnerable [get]
	r.GET("/xss/vulnerable", func(c *gin.Context) {
		input := c.DefaultQuery("input", "<script>alert('XSS')</script>")
		// 취약한 코드 - 직접 출력
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, "<h1>User Input: %s</h1>", input)
	})

	// @Summary XSS - Safe Endpoint
	// @Description Safe endpoint with proper XSS protection
	// @Tags XSS
	// @Param input query string false "Input to test (will be safely escaped)"
	// @Produce html
	// @Success 200 {string} string "HTML response with escaped input"
	// @Router /xss/safe [get]
	r.GET("/xss/safe", func(c *gin.Context) {
		input := c.DefaultQuery("input", "<script>alert('XSS')</script>")
		// 안전한 코드 - HTML 이스케이프
		safeInput := html.EscapeString(input)
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, "<h1>User Input: %s</h1>", safeInput)
	})

	// SQL Injection Test Endpoints
	r.GET("/sql/vulnerable/login", func(c *gin.Context) {
		if sqlInj == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "SQL injection service not available",
			})
			return
		}

		username := c.Query("username")
		password := c.Query("password")
		payload := username
		if payload == "" {
			payload = password
		}
		if payload == "" {
			payload = "' OR '1'='1' --"
		}

		target := "username"
		if username == "" {
			target = "password"
		}

		parameters := map[string]string{
			"test_type": "login",
			"target":    target,
			"username":  username,
			"password":  password,
		}
		if parameters["username"] == "" {
			parameters["username"] = "admin"
		}
		if parameters["password"] == "" {
			parameters["password"] = "password"
		}

		result := sqlInj.ExecuteVulnerableCode(payload, parameters)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    result,
			"metadata": gin.H{
				"language":          "go",
				"vulnerability_type": "sql_injection",
				"mode":              "vulnerable",
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		})
	})

	r.GET("/sql/safe/login", func(c *gin.Context) {
		if sqlInj == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "SQL injection service not available",
			})
			return
		}

		username := c.Query("username")
		password := c.Query("password")
		payload := username
		if payload == "" {
			payload = password
		}
		if payload == "" {
			payload = "admin"
		}

		target := "username"
		if username == "" {
			target = "password"
		}

		parameters := map[string]string{
			"test_type": "login",
			"target":    target,
			"username":  username,
			"password":  password,
		}
		if parameters["username"] == "" {
			parameters["username"] = "admin"
		}
		if parameters["password"] == "" {
			parameters["password"] = "password"
		}

		result := sqlInj.ExecuteSafeCode(payload, parameters)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    result,
			"metadata": gin.H{
				"language":          "go",
				"vulnerability_type": "sql_injection",
				"mode":              "safe",
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		})
	})

	r.GET("/sql/vulnerable/search", func(c *gin.Context) {
		if sqlInj == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "SQL injection service not available",
			})
			return
		}

		query := c.DefaultQuery("query", "' UNION SELECT version(), user(), database() --")

		parameters := map[string]string{
			"test_type": "search",
		}

		result := sqlInj.ExecuteVulnerableCode(query, parameters)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    result,
			"metadata": gin.H{
				"language":          "go",
				"vulnerability_type": "sql_injection",
				"mode":              "vulnerable",
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		})
	})

	r.GET("/sql/safe/search", func(c *gin.Context) {
		if sqlInj == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "SQL injection service not available",
			})
			return
		}

		query := c.DefaultQuery("query", "article")

		parameters := map[string]string{
			"test_type": "search",
		}

		result := sqlInj.ExecuteSafeCode(query, parameters)

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    result,
			"metadata": gin.H{
				"language":          "go",
				"vulnerability_type": "sql_injection",
				"mode":              "safe",
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		})
	})

	// 표준 엔드포인트 추가 (Dashboard 호환성)
	r.POST("/vulnerabilities/sql-injection", func(c *gin.Context) {
		if sqlInj == nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   "SQL injection service not available",
			})
			return
		}

		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid JSON data",
			})
			return
		}

		mode, _ := requestData["mode"].(string)
		if mode == "" {
			mode = "vulnerable"
		}

		username, _ := requestData["username"].(string)
		if username == "" {
			username = "admin"
		}

		password, _ := requestData["password"].(string)
		if password == "" {
			password = "test"
		}

		parameters := map[string]string{
			"test_type": "login",
			"target":    "username",
			"username":  username,
			"password":  password,
		}

		var result interface{}
		if mode == "vulnerable" {
			result = sqlInj.ExecuteVulnerableCode(username, parameters)
		} else {
			result = sqlInj.ExecuteSafeCode(username, parameters)
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    result,
			"metadata": gin.H{
				"language":           "go",
				"vulnerability_type": "sql_injection",
				"mode":               mode,
				"timestamp":          time.Now().Format(time.RFC3339),
			},
		})
	})

	// XSS 표준 엔드포인트 추가 (Dashboard 호환성)
	r.POST("/vulnerabilities/xss", func(c *gin.Context) {
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid JSON data",
			})
			return
		}

		mode, _ := requestData["mode"].(string)
		if mode == "" {
			mode = "vulnerable"
		}

		payload, _ := requestData["payload"].(string)
		if payload == "" {
			payload = `<script>alert("XSS")</script>`
		}

		var result string
		var attackSuccess bool

		if mode == "vulnerable" {
			// 취약한 코드 - 직접 출력
			result = fmt.Sprintf("<h1>User Input: %s</h1>", payload)
			attackSuccess = strings.Contains(payload, "<script>") || strings.Contains(payload, "javascript:")
		} else {
			// 안전한 코드 - HTML 이스케이프
			safeInput := html.EscapeString(payload)
			result = fmt.Sprintf("<h1>User Input: %s</h1>", safeInput)
			attackSuccess = false
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"result":                result,
				"vulnerability_detected": attackSuccess,
				"payload_used":          payload,
				"attack_success":        attackSuccess,
				"execution_time":        "0.001s",
			},
			"metadata": gin.H{
				"language":          "go",
				"vulnerability_type": "xss",
				"mode":              mode,
				"timestamp":         time.Now().Format(time.RFC3339),
			},
		})
	})

	r.GET("/vulnerabilities", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "WebSec-Lab Go Server",
			"available": []string{
				"POST /vulnerabilities/sql-injection",
				"POST /vulnerabilities/xss",
				"GET /xss/vulnerable",
				"GET /xss/safe",
				"GET /sql/vulnerable/login",
				"GET /sql/safe/login",
				"GET /sql/vulnerable/search",
				"GET /sql/safe/search",
			},
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Go server starting on port %s", port)
	r.Run(":" + port)
}