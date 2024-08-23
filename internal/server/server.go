package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/Dorrrke/g1-bookly/internal/domain/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "Secret123Key345Super"

type Claims struct {
	jwt.RegisteredClaims
	UserID string
}

type Repository interface {
	GetAllUsers() ([]models.User, error)
	GetUser(int) (models.User, error)
	GetUserByLogin(string) (models.User, error)
	GetAllBooks() ([]models.Book, error)
	GetBooksByUser(int) ([]models.Book, error)
	InsertUser(models.User) (int, error)
	SaveBook(models.Book) error
	SaveBooks([]models.Book, int) error
	DeleteBooks() error
	SetDeleteStatus(int) error
	DeleteUser(int) error
}

type Server struct {
	Db         Repository
	ErrorChan  chan error
	deleteChan chan int
	log        *zerolog.Logger
}

func New(ctx context.Context, db Repository, zlog *zerolog.Logger) *Server {
	dChan := make(chan int, 5)
	errChan := make(chan error)
	srv := Server{
		Db:         db,
		deleteChan: dChan,
		ErrorChan:  errChan,
		log:        zlog,
	}
	go srv.deleter(ctx)
	return &Server{
		Db:         db,
		deleteChan: dChan,
		ErrorChan:  errChan,
	}
}

func (s *Server) GetUsersHandler(c *gin.Context) {
	users, err := s.Db.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, users)
}

func (s *Server) RegisterHandler(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindBodyWithJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user.Password = string(hash)
	uid, err := s.Db.InsertUser(user)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if !pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusConflict, gin.H{"error": "login alredy used"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	uidStr := strconv.Itoa(uid)
	token, err := createJWTToken(uidStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Authorization", token)
	c.String(http.StatusOK, "User %v was saved", uid)
}

func (s *Server) LoginHandler(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindBodyWithJSON(&user); err != nil {
		s.log.Error().Err(err).Msg("failed parse login data from body")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userFromDb, err := s.Db.GetUserByLogin(user.Login)
	if err != nil {
		s.log.Error().Err(err).Msg("failed get user by login")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(userFromDb.Password), []byte(user.Password)); err != nil {
		s.log.Error().Err(err).Msg("failed get user by login")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Нерная пара логин пароль"})
		return
	}
	uidStr := strconv.Itoa(userFromDb.UID)
	token, err := createJWTToken(uidStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Authorization", token)
	c.String(http.StatusOK, "User %s was logined", user.Name)
}

func (s *Server) AddBook(c *gin.Context) {
	token := c.GetHeader("Authorization")
	uid, err := getUID(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	var book models.Book
	if err := c.ShouldBindBodyWithJSON(&book); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	uidInt, err := strconv.Atoi(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	book.UID = uidInt
	if err := s.Db.SaveBook(book); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.String(http.StatusOK, "Book saved")
}

func (s *Server) AddBooks(c *gin.Context) {
	token := c.GetHeader("Authorization")
	uid, err := getUID(token)
	if err != nil {
		s.log.Error().Err(err).Msg("get uid failed")
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	var books []models.Book
	if err := c.ShouldBindBodyWithJSON(&books); err != nil {
		s.log.Error().Err(err).Msg("parse body failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Println(books)
	uidInt, err := strconv.Atoi(uid)
	if err != nil {
		s.log.Error().Err(err).Msg("parse uid from str to int failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.Db.SaveBooks(books, uidInt); err != nil {
		s.log.Error().Err(err).Msg("save books failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	mes := fmt.Sprintf("Was saved %d books", len(books))
	c.String(http.StatusOK, mes)
}

func (s *Server) GetAllBooks(c *gin.Context) {
	token := c.GetHeader("Authorization")
	_, err := getUID(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	books, err := s.Db.GetAllBooks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, books)
}

func (s *Server) GetBooksByUser(c *gin.Context) {
	token := c.GetHeader("Authorization")
	uIdStr, err := getUID(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	uId, err := strconv.Atoi(uIdStr)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	books, err := s.Db.GetBooksByUser(uId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, books)
}

func (s *Server) GetUserHandler(c *gin.Context) {
	param := c.Query("uid")
	log.Println("Param from url - " + param)
	uid, err := strconv.Atoi(param)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid argument"})
		return
	}
	log.Printf("UID - %v", uid)
	user, err := s.Db.GetUser(uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, user)
}

func (s *Server) DeleteBook(c *gin.Context) {
	token := c.GetHeader("Authorization")
	_, err := getUID(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	bid := c.Param("id")
	bIdInt, err := strconv.Atoi(bid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.Db.SetDeleteStatus(bIdInt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.deleteChan <- bIdInt
	c.String(http.StatusOK, "Book was deleted")
}

func (s *Server) deleter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if len(s.deleteChan) == 5 {
				for i := 0; i < 5; i++ {
					<-s.deleteChan
				}
				if err := s.Db.DeleteBooks(); err != nil {
					s.ErrorChan <- err
					return
				}
			}
		}
	}
}

func createJWTToken(uid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 3)),
		},
		UserID: uid,
	})
	key := []byte(SecretKey)
	tokenStr, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func getUID(tokenStr string) (string, error) {
	claim := &Claims{}

	token, err := jwt.ParseWithClaims(tokenStr, claim, func(t *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	return claim.UserID, nil
}
