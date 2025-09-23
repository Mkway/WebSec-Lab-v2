package main

import (
	"html"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

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
			"endpoints": []string{"/health", "/xss/vulnerable", "/xss/safe"},
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

	r.GET("/vulnerabilities", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message":   "WebSec-Lab Go Server",
			"available": []string{"GET /xss/vulnerable", "GET /xss/safe"},
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Go server starting on port %s", port)
	r.Run(":" + port)
}