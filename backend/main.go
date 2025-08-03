package main

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type StringArray []string

func (sa *StringArray) Scan(value interface{}) error {
	if value == nil {
		*sa = []string{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan StringArray: expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, sa)
}

func (sa StringArray) Value() (driver.Value, error) {
	if len(sa) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(sa)
}

var db *gorm.DB
var clients = make(map[int]*websocket.Conn)
var r *gin.Engine

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type User struct {
	ID          int         `json:"id" gorm:"primaryKey"`
	Username    string      `json:"username" gorm:"unique;not null"`
	Email       string      `json:"email" gorm:"unique;not null"`
	Password    string      `json:"password" gorm:"not null"`
	Role        string      `json:"role" gorm:"not null"`
	FullName    string      `json:"full_name"`
	Description string      `json:"description"`
	AvatarURL   string      `json:"avatar_url"`
	Services    StringArray `json:"services" gorm:"type:jsonb"`
	CreatedAt   time.Time   `json:"created_at" gorm:"autoCreateTime"`
}

type Course struct {
	ID          int             `json:"id" gorm:"primaryKey"`
	TeacherID   int             `json:"teacher_id"`
	Title       string          `json:"title" gorm:"not null"`
	Services    StringArray     `json:"services" gorm:"type:jsonb"`
	Description string          `json:"description" gorm:"not null"`
	Price       decimal.Decimal `json:"price" gorm:"type:decimal(10,2);not null"`
	VideoURL    string          `json:"video_url"`
	Teacher     User            `json:"teacher" gorm:"foreignKey:TeacherID"`
	CreatedAt   time.Time       `json:"created_at" gorm:"autoCreateTime"`
}

type Payment struct {
	ID            int             `json:"id" gorm:"primaryKey"`
	UserID        int             `json:"user_id"`
	CourseID      int             `json:"course_id"`
	Amount        decimal.Decimal `json:"amount" gorm:"type:decimal(10,2);not null"`
	Commission    decimal.Decimal `json:"commission" gorm:"type:decimal(10,2);not null"`
	NetAmount     decimal.Decimal `json:"net_amount" gorm:"type:decimal(10,2);not null"`
	Status        string          `json:"status" gorm:"default:'pending'"`
	TransactionID string          `json:"transaction_id"`
	CreatedAt     time.Time       `json:"created_at" gorm:"autoCreateTime"`
}

type Message struct {
	ID         int       `json:"id" gorm:"primaryKey"`
	SenderID   int       `json:"sender_id"`
	ReceiverID int       `json:"receiver_id"`
	CourseID   *int      `json:"course_id"`
	Content    string    `json:"content" gorm:"not null"`
	Read       bool      `json:"read" gorm:"default:false"`
	CreatedAt  time.Time `json:"created_at" gorm:"autoCreateTime"`
}

type Notification struct {
	ID        int       `json:"id" gorm:"primaryKey"`
	UserID    int       `json:"user_id"`
	Type      string    `json:"type" gorm:"not null"`
	RelatedID int       `json:"related_id"`
	Content   string    `json:"content" gorm:"not null"`
	Read      bool      `json:"read" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`
}

type Review struct {
	ID             int       `json:"id" gorm:"primaryKey"`
	CourseID       int       `json:"course_id"`
	AuthorID       int       `json:"author_id"`
	ReviewedUserID int       `json:"reviewed_user_id"`
	Content        string    `json:"content" gorm:"not null"`
	CreatedAt      time.Time `json:"created_at" gorm:"autoCreateTime"`
}

type Dialog struct {
	UserID      int    `json:"user_id"`
	FullName    string `json:"full_name"`
	AvatarURL   string `json:"avatar_url"`
	LastMessage string `json:"last_message"`
	UnreadCount int    `json:"unread_count"`
}

func main() {
	if os.Getenv("JWT_SECRET") == "" {
		panic("JWT_SECRET not set")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=adminadmiadmadanim dbname=education_for sslmode=disable"
	}
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Не удалось подключиться к базе данных: " + err.Error())
	}
	db.AutoMigrate(&User{}, &Course{}, &Payment{}, &Message{}, &Notification{}, &Review{})

	// Test data for development
	testPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	db.Create(&User{Username: "nutri1", Email: "nutri1@example.com", Password: string(testPassword), Role: "nutri", FullName: "Nutri One", Description: "Expert in nutrition", AvatarURL: "/images/nutri-placeholder.jpg"})
	db.Create(&Course{TeacherID: 1, Title: "Nutrition Course 1", Services: StringArray{"Consultation"}, Description: "Learn nutrition basics", Price: decimal.NewFromFloat(100.00), VideoURL: "https://example.com/video1"})
	db.Create(&Course{TeacherID: 1, Title: "Nutrition Course 2", Services: StringArray{"Detox"}, Description: "Detox program", Price: decimal.NewFromFloat(200.00), VideoURL: "https://example.com/video2"})
	db.Create(&User{Username: "client1", Email: "client1@example.com", Password: string(testPassword), Role: "client", FullName: "Client One"})

	r = gin.Default()

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

	r.GET("/api", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "API is running"})
	})

	r.POST("/api/register", registerUser)
	r.POST("/api/login", loginUser)
	r.GET("/api/profile", authMiddleware(), getOwnProfile)
	r.GET("/api/profile/:id", getOtherProfile)
	r.PUT("/api/profile", authMiddleware(), updateProfile)
	r.GET("/api/search", searchCourses)
	r.GET("/api/courses", authMiddleware(), getCourses)
	r.POST("/api/courses", authMiddleware("nutri"), createCourse)
	r.PUT("/api/courses/:id", authMiddleware("nutri"), updateCourse)
	r.GET("/api/courses/:id", getCourseById)
	r.DELETE("/api/courses/:id", authMiddleware("nutri"), deleteCourse)
	r.POST("/api/payments/simulate", authMiddleware("client"), simulatePayment)
	r.GET("/api/payments", authMiddleware(), getPayments)
	r.GET("/api/enrolled", authMiddleware("client"), getEnrolledCourses)
	r.POST("/api/messages", authMiddleware(), sendMessage)
	r.GET("/api/messages", authMiddleware(), getMessages)
	r.PUT("/api/messages/read", authMiddleware(), markMessagesRead)
	r.GET("/api/notifications", authMiddleware(), getNotifications)
	r.PUT("/api/notifications/:id/read", authMiddleware(), markNotificationRead)
	r.POST("/api/reviews", authMiddleware("client"), createReview)
	r.GET("/api/reviews/user/:user_id", getReviewsByUser)
	r.GET("/api/reviews/course/:course_id", getReviewsByCourse)
	r.GET("/api/nutris", getNutris)
	r.GET("/api/reviews/random", getRandomReviews)
	r.POST("/api/start-chat", authMiddleware(), startChat)
	r.GET("/api/chats", authMiddleware(), getChats)
	r.GET("/ws", func(c *gin.Context) {
		handleWebSocket(c.Writer, c.Request)
	})

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Ошибка запуска сервера: ", err)
	}
}

func authMiddleware(requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" || len(tokenString) <= 7 || tokenString[:7] != "Bearer " {
			if c.Request.Method == "GET" && c.Request.URL.Path == "/api/payments" {
				c.JSON(http.StatusOK, []Payment{})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен не предоставлен"})
			c.Abort()
			return
		}
		tokenString = tokenString[7:]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен"})
			c.Abort()
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные данные токена"})
			c.Abort()
			return
		}
		userID := int(claims["id"].(float64))
		role := claims["role"].(string)
		c.Set("user_id", userID)
		c.Set("role", role)
		if len(requiredRoles) > 0 && !containsRole(requiredRoles, role) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func containsRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if user.Role == "nutri" && user.Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Описание обязательно для нутрициолога"})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось хэшировать пароль"})
		return
	}
	user.Password = string(hashedPassword)
	if user.AvatarURL == "" {
		user.AvatarURL = "/images/nutri-placeholder.jpg"
	}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось создать пользователя: " + err.Error()})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   user.ID,
		"role": user.Role,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сгенерировать токен"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"token": tokenString, "role": user.Role, "id": user.ID})
}

func loginUser(c *gin.Context) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user User
	if err := db.Where("username = ?", creds.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   user.ID,
		"role": user.Role,
		"exp":  time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось сгенерировать токен"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tokenString, "role": user.Role, "id": user.ID})
}

func getOwnProfile(c *gin.Context) {
	userID := c.GetInt("user_id")
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}
	user.Password = ""
	var courses []Course
	db.Where("teacher_id = ?", userID).Find(&courses)
	c.JSON(http.StatusOK, gin.H{"profile": user, "courses": courses})
}

func getOtherProfile(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	var user User
	if err := db.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}
	user.Password = ""
	var courses []Course
	db.Where("teacher_id = ?", id).Find(&courses)
	c.JSON(http.StatusOK, gin.H{"profile": user, "courses": courses})
}

func updateProfile(c *gin.Context) {
	userID := c.GetInt("user_id")
	var input User
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := db.Model(&User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"full_name":   input.FullName,
		"description": input.Description,
		"avatar_url":  input.AvatarURL,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обновить профиль"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Профиль обновлен"})
}

func searchCourses(c *gin.Context) {
	query := c.Query("q")
	var courses []Course
	q := db.Preload("Teacher").Where("teacher_id IN (SELECT id FROM users WHERE role = 'nutri')")
	if query != "" {
		query = "%" + strings.ToLower(query) + "%"
		q = q.Where("LOWER(title) LIKE ? OR LOWER(description) LIKE ?", query, query)
	}
	if err := q.Order("title ASC, id ASC").Find(&courses).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка поиска курсов"})
		return
	}
	for i := range courses {
		courses[i].Teacher.Password = ""
	}
	c.JSON(http.StatusOK, courses)
}

func getCourses(c *gin.Context) {
	var courses []Course
	teacherID := c.GetInt("user_id")
	if err := db.Preload("Teacher").Where("teacher_id = ?", teacherID).Find(&courses).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки курсов"})
		return
	}
	for i := range courses {
		courses[i].Teacher.Password = ""
	}
	c.JSON(http.StatusOK, courses)
}

func createCourse(c *gin.Context) {
	var course Course
	if err := c.ShouldBindJSON(&course); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат данных: " + err.Error()})
		return
	}
	if course.Price.LessThanOrEqual(decimal.Zero) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Стоимость должна быть больше 0"})
		return
	}
	if len(course.Services) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Укажите хотя бы одну услугу"})
		return
	}
	course.TeacherID = c.GetInt("user_id")
	if err := db.Create(&course).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не удалось создать курс: " + err.Error()})
		return
	}
	c.JSON(http.StatusCreated, course)
}

func updateCourse(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	var course Course
	if err := c.ShouldBindJSON(&course); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	course.ID = id
	if err := db.Where("id = ? AND teacher_id = ?", id, c.GetInt("user_id")).Updates(&course).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Курс не найден или не принадлежит вам"})
		return
	}
	c.JSON(http.StatusOK, course)
}

func getCourseById(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	var course Course
	if err := db.Preload("Teacher").First(&course, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Курс не найден"})
		return
	}
	course.Teacher.Password = ""
	c.JSON(http.StatusOK, course)
}

func deleteCourse(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	if err := db.Where("id = ? AND teacher_id = ?", id, c.GetInt("user_id")).Delete(&Course{}).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Курс не найден или не принадлежит вам"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Курс удален"})
}

func simulatePayment(c *gin.Context) {
	var input struct {
		CourseID int             `json:"course_id"`
		UserID   int             `json:"user_id"`
		Amount   decimal.Decimal `json:"amount"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var course Course
	if err := db.First(&course, input.CourseID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Курс не найден"})
		return
	}
	var existing Payment
	if db.Where("user_id = ? AND course_id = ? AND status = 'success'", input.UserID, input.CourseID).First(&existing).Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Курс уже оплачен"})
		return
	}
	if !input.Amount.Equal(course.Price) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверная сумма оплаты"})
		return
	}
	amount := input.Amount
	commission := amount.Mul(decimal.NewFromFloat(0.05))
	netAmount := amount.Sub(commission)
	transactionID := "TX-" + strconv.Itoa(rand.Intn(1000000))
	payment := Payment{
		UserID:        input.UserID,
		CourseID:      input.CourseID,
		Amount:        amount,
		Commission:    commission,
		NetAmount:     netAmount,
		Status:        "success",
		TransactionID: transactionID,
		CreatedAt:     time.Now(),
	}
	if err := db.Create(&payment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось обработать платеж"})
		return
	}
	var notiTeacher Notification
	notiTeacher.UserID = course.TeacherID
	notiTeacher.Type = "payment"
	notiTeacher.RelatedID = payment.ID
	notiTeacher.Content = fmt.Sprintf("Клиент оплатил курс %s: %s RUB", course.Title, netAmount.String())
	notiTeacher.Read = false
	notiTeacher.CreatedAt = time.Now()
	db.Create(&notiTeacher)
	jsonNotiTeacher, _ := json.Marshal(notiTeacher)
	sendToUser(course.TeacherID, []byte(`{"type":"notification","data":`+string(jsonNotiTeacher)+`}`))
	var notiClient Notification
	notiClient.UserID = input.UserID
	notiClient.Type = "payment"
	notiClient.RelatedID = payment.ID
	notiClient.Content = "Оплата за курс " + course.Title + " успешна"
	notiClient.Read = false
	notiClient.CreatedAt = time.Now()
	db.Create(&notiClient)
	jsonNotiClient, _ := json.Marshal(notiClient)
	sendToUser(input.UserID, []byte(`{"type":"notification","data":`+string(jsonNotiClient)+`}`))
	c.JSON(http.StatusOK, gin.H{"transaction_id": transactionID, "status": "success"})
}

func getPayments(c *gin.Context) {
	userID := c.GetInt("user_id")
	var payments []Payment
	if userID == 0 {
		c.JSON(http.StatusOK, []Payment{})
		return
	}
	db.Where("user_id = ? AND status = 'success'", userID).Find(&payments)
	c.JSON(http.StatusOK, payments)
}

func getEnrolledCourses(c *gin.Context) {
	userID := c.GetInt("user_id")
	var payments []Payment
	db.Where("user_id = ? AND status = 'success'", userID).Find(&payments)
	courseIDs := []int{}
	for _, p := range payments {
		courseIDs = append(courseIDs, p.CourseID)
	}
	var courses []Course
	db.Preload("Teacher").Where("id IN ?", courseIDs).Find(&courses)
	c.JSON(http.StatusOK, courses)
}

func sendMessage(c *gin.Context) {
	var msg Message
	if err := c.ShouldBindJSON(&msg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var receiver User
	if err := db.First(&receiver, msg.ReceiverID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Получатель не существует"})
		return
	}
	msg.SenderID = c.GetInt("user_id")
	msg.Read = false
	msg.CreatedAt = time.Now()
	if err := db.Create(&msg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось отправить сообщение"})
		return
	}
	var sender User
	db.First(&sender, msg.SenderID)
	var noti Notification
	noti.UserID = msg.ReceiverID
	noti.Type = "message"
	noti.RelatedID = msg.SenderID
	noti.Content = "Новое сообщение от " + sender.FullName
	noti.Read = false
	noti.CreatedAt = time.Now()
	db.Create(&noti)
	jsonMsg, _ := json.Marshal(msg)
	sendToUser(msg.ReceiverID, []byte(`{"type":"message","data":`+string(jsonMsg)+`}`))
	jsonNoti, _ := json.Marshal(noti)
	sendToUser(msg.ReceiverID, []byte(`{"type":"notification","data":`+string(jsonNoti)+`}`))
	c.JSON(http.StatusCreated, msg)
}

func getMessages(c *gin.Context) {
	receiverIDStr := c.Query("receiver_id")
	receiverID, err := strconv.Atoi(receiverIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID получателя"})
		return
	}
	userID := c.GetInt("user_id")
	var messages []Message
	db.Where("(sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)", userID, receiverID, receiverID, userID).
		Order("created_at ASC").
		Find(&messages)
	c.JSON(http.StatusOK, messages)
}

func markMessagesRead(c *gin.Context) {
	receiverIDStr := c.Query("receiver_id")
	receiverID, err := strconv.Atoi(receiverIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID получателя"})
		return
	}
	userID := c.GetInt("user_id")
	if err := db.Model(&Message{}).Where("sender_id = ? AND receiver_id = ?", receiverID, userID).Update("read", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка отметки прочитанных"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "marked as read"})
}

func getNotifications(c *gin.Context) {
	userID := c.GetInt("user_id")
	var notifications []Notification
	db.Where("user_id = ?", userID).Order("created_at DESC").Find(&notifications)
	c.JSON(http.StatusOK, notifications)
}

func markNotificationRead(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	userID := c.GetInt("user_id")
	if err := db.Model(&Notification{}).Where("id = ? AND user_id = ?", id, userID).Update("read", true).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Уведомление не найдено"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Уведомление отмечено как прочитанное"})
}

func createReview(c *gin.Context) {
	var review Review
	if err := c.ShouldBindJSON(&review); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var course Course
	if err := db.First(&course, review.CourseID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Курс не найден"})
		return
	}
	review.ReviewedUserID = course.TeacherID
	review.AuthorID = c.GetInt("user_id")
	review.CreatedAt = time.Now()
	if err := db.Create(&review).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать отзыв"})
		return
	}
	c.JSON(http.StatusCreated, review)
}

func getReviewsByUser(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("user_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	var reviews []Review
	db.Where("reviewed_user_id = ?", userID).Find(&reviews)
	c.JSON(http.StatusOK, reviews)
}

func getReviewsByCourse(c *gin.Context) {
	courseID, err := strconv.Atoi(c.Param("course_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}
	var reviews []Review
	db.Where("course_id = ?", courseID).Find(&reviews)
	c.JSON(http.StatusOK, reviews)
}

func getNutris(c *gin.Context) {
	limitStr := c.Query("limit")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 6
	}
	if limit > 100 {
		limit = 100
	}
	var users []User
	if err := db.Where("role = ?", "nutri").Limit(limit).Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки нутрициологов"})
		return
	}
	if len(users) == 0 {
		c.JSON(http.StatusOK, []User{})
		return
	}
	for i := range users {
		users[i].Password = ""
	}
	c.JSON(http.StatusOK, users)
}

func getRandomReviews(c *gin.Context) {
	var reviews []Review
	db.Order("RANDOM()").Limit(3).Find(&reviews)
	c.JSON(http.StatusOK, reviews)
}

func startChat(c *gin.Context) {
	var input struct {
		ReceiverID int `json:"receiver_id"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var receiver User
	if err := db.First(&receiver, input.ReceiverID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пользователь не найден"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"receiver_id": input.ReceiverID})
}

func getChats(c *gin.Context) {
	userID := c.GetInt("user_id")
	var dialogs []Dialog
	var unread int64
	if err := db.Raw(`
		SELECT u.id AS user_id, u.full_name, u.avatar_url, m.content AS last_message, 
		COUNT(CASE WHEN m.read = false AND m.sender_id != ? THEN 1 END) AS unread_count
		FROM users u
		JOIN messages m ON (m.sender_id = u.id AND m.receiver_id = ?) OR (m.receiver_id = u.id AND m.sender_id = ?)
		WHERE u.id != ?
		GROUP BY u.id, u.full_name, u.avatar_url, m.content, m.created_at
		ORDER BY m.created_at DESC
	`, userID, userID, userID, userID).Scan(&dialogs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка загрузки чатов"})
		return
	}
	for i := range dialogs {
		db.Model(&Message{}).Where("receiver_id = ? AND sender_id = ? AND read = false", userID, dialogs[i].UserID).Count(&unread)
		dialogs[i].UnreadCount = int(unread)
	}
	c.JSON(http.StatusOK, dialogs)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Ошибка апгрейда WebSocket: %v", err)
		return
	}
	defer conn.Close()

	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		conn.WriteMessage(websocket.TextMessage, []byte("Токен не предоставлен"))
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		conn.WriteMessage(websocket.TextMessage, []byte("Неверный токен"))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		conn.WriteMessage(websocket.TextMessage, []byte("Неверные данные токена"))
		return
	}

	userID := int(claims["id"].(float64))
	clients[userID] = conn

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Ошибка чтения WebSocket для пользователя %d: %v", userID, err)
			delete(clients, userID)
			break
		}
		var input struct {
			ReceiverID int    `json:"receiver_id"`
			Content    string `json:"content"`
		}
		if err := json.Unmarshal(message, &input); err != nil {
			log.Printf("Ошибка парсинга JSON: %v", err)
			continue
		}
		newMessage := Message{
			SenderID:   userID,
			ReceiverID: input.ReceiverID,
			Content:    input.Content,
			CreatedAt:  time.Now(),
		}
		if err := db.Create(&newMessage).Error; err != nil {
			log.Printf("Ошибка создания сообщения: %v", err)
			continue
		}
		broadcastMessage(newMessage)
	}
}

func broadcastMessage(message Message) {
	for userID, conn := range clients {
		if userID == message.SenderID || userID == message.ReceiverID {
			continue
		}
		if err := conn.WriteJSON(message); err != nil {
			log.Printf("Ошибка отправки сообщения пользователю %d: %v", userID, err)
			conn.Close()
			delete(clients, userID)
		}
	}
}

func sendToUser(userID int, message []byte) {
	if conn, ok := clients[userID]; ok {
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			log.Printf("Ошибка отправки WebSocket сообщения пользователю %d: %v", userID, err)
			conn.Close()
			delete(clients, userID)
		}
	}
}
