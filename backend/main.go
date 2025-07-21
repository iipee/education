package main

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID          int      `json:"id" gorm:"primaryKey"`
	Username    string   `json:"username" gorm:"unique"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	Description string   `json:"description"`
	Services    []string `json:"services" gorm:"type:text[]"`
}

type Course struct {
	ID          int     `json:"id" gorm:"primaryKey"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	TeacherID   int     `json:"teacher_id"`
	VideoURL    string  `json:"video_url"`
	Price       float64 `json:"price"`
}

type Order struct {
	ID             int     `json:"id" gorm:"primaryKey"`
	ClientID       int     `json:"client_id"`
	NutritionistID int     `json:"nutritionist_id"`
	CourseID       int     `json:"course_id"`
	Status         string  `json:"status"`
	Price          float64 `json:"price"`
}

type Review struct {
	ID       int    `json:"id" gorm:"primaryKey"`
	OrderID  int    `json:"order_id"`
	Text     string `json:"text"`
	AuthorID int    `json:"author_id"`
}

var db *gorm.DB

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=admin dbname=education_for sslmode=disable"
	}
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect database: " + err.Error())
	}
	db.AutoMigrate(&User{}, &Course{}, &Order{}, &Review{})

	r := gin.Default()

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

	r.POST("/api/register", registerUser)
	r.POST("/api/login", loginUser)
	r.GET("/api/profile", authMiddleware(), getProfile)
	r.GET("/api/search", authMiddleware(), searchNutritionists)
	r.GET("/api/courses", authMiddleware(), getCourses)
	r.POST("/api/courses", authMiddleware("nutritionist"), createCourse)
	r.PUT("/api/courses/:id", authMiddleware("nutritionist"), updateCourse)
	r.GET("/api/courses/:id", authMiddleware(), getCourseById)
	r.DELETE("/api/courses/:id", authMiddleware("nutritionist"), deleteCourse)
	r.POST("/api/orders", authMiddleware("client"), createOrder)
	r.GET("/api/orders", authMiddleware(), getOrders)
	r.POST("/api/reviews", authMiddleware("client"), createReview)
	r.GET("/api/reviews/:course_id", authMiddleware(), getReviewsByCourse)
	r.POST("/api/payment", authMiddleware("client"), createPayment) // Симуляция

	r.Run(":8080")
}

func authMiddleware(requiredRole ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token provided"})
			c.Abort()
			return
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		claims, _ := token.Claims.(jwt.MapClaims)
		userID := int(claims["id"].(float64))
		role := claims["role"].(string)
		c.Set("user_id", userID)
		c.Set("role", role)
		if len(requiredRole) > 0 && role != requiredRole[0] {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to hash password"})
		return
	}
	user.Password = string(hashedPassword)
	db.Create(&user)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}
	c.JSON(201, gin.H{"token": tokenString, "role": user.Role})
}

func loginUser(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var user User
	if err := db.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}
	c.JSON(200, gin.H{"token": tokenString, "role": user.Role})
}

func getProfile(c *gin.Context) {
	userID := c.GetInt("user_id")
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}
	c.JSON(200, user)
}

func searchNutritionists(c *gin.Context) {
	query := c.Query("q")
	var users []User
	db.Where("role = ? AND (username LIKE ? OR description LIKE ?)", "nutritionist", "%"+query+"%", "%"+query+"%").Find(&users)
	c.JSON(200, users)
}

func getCourses(c *gin.Context) {
	var courses []Course
	db.Find(&courses)
	c.JSON(200, courses)
}

func createCourse(c *gin.Context) {
	var course Course
	if err := c.ShouldBindJSON(&course); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	course.TeacherID = c.GetInt("user_id")
	db.Create(&course)
	c.JSON(201, course)
}

func updateCourse(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	var course Course
	if err := c.ShouldBindJSON(&course); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	course.ID = id
	if err := db.Where("id = ? AND teacher_id = ?", id, c.GetInt("user_id")).Updates(&course).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Course not found or not owned"})
		return
	}
	c.JSON(http.StatusOK, course)
}

func getCourseById(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	var course Course
	if err := db.First(&course, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Course not found"})
		return
	}
	c.JSON(http.StatusOK, course)
}

func deleteCourse(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	if err := db.Where("id = ? AND teacher_id = ?", id, c.GetInt("user_id")).Delete(&Course{}).Error; err != nil {
		c.JSON(404, gin.H{"error": "Course not found or not owned"})
		return
	}
	c.JSON(200, gin.H{"message": "Course deleted"})
}

func createOrder(c *gin.Context) {
	var order Order
	if err := c.ShouldBindJSON(&order); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	order.ClientID = c.GetInt("user_id")
	order.Status = "pending"
	db.Create(&order)
	c.JSON(201, order)
}

func getOrders(c *gin.Context) {
	userID := c.GetInt("user_id")
	role := c.GetString("role")
	var orders []Order
	if role == "nutritionist" {
		db.Where("nutritionist_id = ?", userID).Find(&orders)
	} else {
		db.Where("client_id = ?", userID).Find(&orders)
	}
	c.JSON(200, orders)
}

func createReview(c *gin.Context) {
	var review Review
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	review.AuthorID = c.GetInt("user_id")
	db.Create(&review)
	c.JSON(201, review)
}

func getReviewsByCourse(c *gin.Context) {
	courseID, err := strconv.Atoi(c.Param("course_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}
	var reviews []Review
	db.Where("order_id IN (SELECT id FROM orders WHERE course_id = ?)", courseID).Find(&reviews)
	c.JSON(200, reviews)
}

func createPayment(c *gin.Context) {
	c.JSON(200, gin.H{"message": "Тест оплаты прошел успешно"})
}
