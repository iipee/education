package main

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
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

// StringArray - пользовательский тип для обработки jsonb как []string
type StringArray []string

func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = []string{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan StringArray: expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, a)
}

func (a StringArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(a)
}

var db *gorm.DB
var clients = make(map[int]*websocket.Conn)

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
	Teacher     User            `gorm:"foreignKey:TeacherID"`
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
	r.GET("/api/profile", authMiddleware(), getOwnProfile)
	r.GET("/api/profile/:id", authMiddleware(), getOtherProfile)
	r.PUT("/api/profile", authMiddleware(), updateProfile)
	r.GET("/api/search", searchCourses)
	r.GET("/api/courses", authMiddleware(), getCourses)
	r.POST("/api/courses", authMiddleware("nutri"), createCourse)
	r.PUT("/api/courses/:id", authMiddleware("nutri"), updateCourse)
	r.GET("/api/courses/:id", authMiddleware(), getCourseById)
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
	r.GET("/api/reviews/user/:user_id", authMiddleware(), getReviewsByUser)
	r.GET("/api/reviews/course/:course_id", authMiddleware(), getReviewsByCourse)
	r.GET("/api/nutris", getNutris)
	r.GET("/api/reviews/random", getRandomReviews)
	r.GET("/ws", handleWebSocket)

	r.Run(":8080")
}

func authMiddleware(requiredRole ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" || len(tokenString) <= 7 || tokenString[:7] != "Bearer " {
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
		claims, _ := token.Claims.(jwt.MapClaims)
		userID := int(claims["id"].(float64))
		role := claims["role"].(string)
		c.Set("user_id", userID)
		c.Set("role", role)
		if len(requiredRole) > 0 && role != requiredRole[0] {
			c.JSON(http.StatusForbidden, gin.H{"error": "Недостаточно прав"})
			c.Abort()
			return
		}
		c.Next()
	}
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
		"services":    input.Services,
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
		query = strings.ToLower(query)
		q = q.Where("LOWER(title) LIKE ? OR LOWER(description) LIKE ?", "%"+query+"%", "%"+query+"%")
	}
	q.Order("title ASC, id ASC").Find(&courses)
	c.JSON(http.StatusOK, courses)
}

func getCourses(c *gin.Context) {
	var courses []Course
	q := db.Preload("Teacher")
	teacherIDStr := c.Query("teacher_id")
	var teacherID int
	if teacherIDStr == "" {
		teacherID = c.GetInt("user_id")
	} else {
		teacherID, _ = strconv.Atoi(teacherIDStr)
	}
	q.Where("teacher_id = ?", teacherID).Find(&courses)
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
		CourseID int `json:"course_id"`
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
	if db.Where("user_id = ? AND course_id = ? AND status = 'success'", c.GetInt("user_id"), input.CourseID).First(&existing).Error == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Курс уже оплачен"})
		return
	}
	amount := course.Price
	commission := amount.Mul(decimal.NewFromFloat(0.5))
	netAmount := amount.Sub(commission)
	transactionID := "fake_" + strconv.Itoa(rand.Intn(1000000))
	payment := Payment{
		UserID:        c.GetInt("user_id"),
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
	notiTeacher.Content = "Получен новый платеж за курс: " + course.Title
	notiTeacher.Read = false
	notiTeacher.CreatedAt = time.Now()
	db.Create(&notiTeacher)
	jsonNotiTeacher, _ := json.Marshal(notiTeacher)
	sendToUser(course.TeacherID, []byte(`{"type":"notification","data":`+string(jsonNotiTeacher)+`}`))
	var notiClient Notification
	notiClient.UserID = c.GetInt("user_id")
	notiClient.Type = "payment"
	notiClient.RelatedID = payment.ID
	notiClient.Content = "Оплата за курс " + course.Title + " успешна"
	notiClient.Read = false
	notiClient.CreatedAt = time.Now()
	db.Create(&notiClient)
	jsonNotiClient, _ := json.Marshal(notiClient)
	sendToUser(c.GetInt("user_id"), []byte(`{"type":"notification","data":`+string(jsonNotiClient)+`}`))
	c.JSON(http.StatusOK, gin.H{"transaction_id": transactionID, "status": "success"})
}

func getPayments(c *gin.Context) {
	userID := c.GetInt("user_id")
	role := c.GetString("role")
	var payments []Payment
	if role == "nutri" {
		db.Joins("JOIN courses ON courses.id = payments.course_id").Where("courses.teacher_id = ? AND payments.status = 'success'", userID).Find(&payments)
	} else {
		db.Where("user_id = ? AND status = 'success'", userID).Find(&payments)
	}
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
	noti.Content = "Новое сообщение от " + sender.Username
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
	db.Where("sender_id = ? AND receiver_id = ?", receiverID, userID).Update("read", true)
	c.JSON(http.StatusOK, gin.H{"message": "Сообщения отмечены как прочитанные"})
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
	var users []User
	db.Where("role = 'nutri'").Limit(3).Find(&users)
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

func handleWebSocket(c *gin.Context) {
	tokenString := c.Query("token")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверный токен"})
		return
	}
	claims, _ := token.Claims.(jwt.MapClaims)
	userID := int(claims["id"].(float64))
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	clients[userID] = conn
	defer func() {
		conn.Close()
		delete(clients, userID)
	}()
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func sendToUser(userID int, message []byte) {
	if conn, ok := clients[userID]; ok {
		if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
			conn.Close()
			delete(clients, userID)
		}
	}
}
