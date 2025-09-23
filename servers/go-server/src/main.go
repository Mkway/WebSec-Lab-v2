package main

import (
	"html"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"./sqlinjection"
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

	// Routes
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"service":   "websec-go",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":   "WebSec-Lab Go Server",
			"version":   "2.0.0",
			"endpoints": []string{"/health", "/xss/vulnerable", "/xss/safe", "/sql/vulnerable/login", "/sql/safe/login", "/sql/vulnerable/search", "/sql/safe/search"},
		})
	})

	// XSS Test Endpoints
	r.GET("/xss/vulnerable", func(c *gin.Context) {
		input := c.DefaultQuery("input", "<script>alert('XSS')</script>")
		// 취약한 코드 - 직접 출력
		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, "<h1>User Input: %s</h1>", input)
	})

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

	r.GET("/vulnerabilities", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":   "WebSec-Lab Go Server",
			"available": []string{"GET /xss/vulnerable", "GET /xss/safe", "GET /sql/vulnerable/login", "GET /sql/safe/login", "GET /sql/vulnerable/search", "GET /sql/safe/search"},
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Go server starting on port %s", port)
	r.Run(":" + port)
}