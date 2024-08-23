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

const tokenTimout = time.Hour * 3

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
	DB         Repository
	ErrorChan  chan error
	deleteChan chan int
	log        *zerolog.Logger
}

func New(ctx context.Context, dataBase Repository, zlog *zerolog.Logger) *Server {
	dChan := make(chan int, 5) //nolint: gomnd // todo const
	errChan := make(chan error)
	srv := Server{
		DB:         dataBase,
		deleteChan: dChan,
		ErrorChan:  errChan,
		log:        zlog,
	}
	go srv.deleter(ctx)
	return &Server{
		DB:         dataBase,
		deleteChan: dChan,
		ErrorChan:  errChan,
	}
}

func (s *Server) GetUsersHandler(ginCtx *gin.Context) {
	users, err := s.DB.GetAllUsers()
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, users)
}

func (s *Server) RegisterHandler(ginCtx *gin.Context) {
	var user models.User
	if err := ginCtx.ShouldBindBodyWithJSON(&user); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	user.Password = string(hash)
	uid, err := s.DB.InsertUser(user)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if !pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
				ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			ginCtx.JSON(http.StatusConflict, gin.H{"error": "login alredy used"})
			return
		}
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	uidStr := strconv.Itoa(uid)
	token, err := createJWTToken(uidStr)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.Header("Authorization", token)
	ginCtx.String(http.StatusOK, "User %v was saved", uid)
}

func (s *Server) LoginHandler(ginCtx *gin.Context) {
	var user models.User
	if err := ginCtx.ShouldBindBodyWithJSON(&user); err != nil {
		s.log.Error().Err(err).Msg("failed parse login data from body")
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userFromDB, err := s.DB.GetUserByLogin(user.Login)
	if err != nil {
		s.log.Error().Err(err).Msg("failed get user by login")
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err = bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(user.Password)); err != nil {
		s.log.Error().Err(err).Msg("failed get user by login")
		ginCtx.JSON(http.StatusUnauthorized, gin.H{"error": "Нерная пара логин пароль"})
		return
	}
	uidStr := strconv.Itoa(userFromDB.UID)
	token, err := createJWTToken(uidStr)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.Header("Authorization", token)
	ginCtx.String(http.StatusOK, "User %s was logined", user.Name)
}

func (s *Server) AddBook(ginCtx *gin.Context) {
	token := ginCtx.GetHeader("Authorization")
	uid, err := getUID(token)
	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	var book models.Book
	if err = ginCtx.ShouldBindBodyWithJSON(&book); err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	uidInt, err := strconv.Atoi(uid)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	book.UID = uidInt
	if err = s.DB.SaveBook(book); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.String(http.StatusOK, "Book saved")
}

func (s *Server) AddBooks(ginCtx *gin.Context) {
	token := ginCtx.GetHeader("Authorization")
	uid, err := getUID(token)
	if err != nil {
		s.log.Error().Err(err).Msg("get uid failed")
		ginCtx.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	var books []models.Book
	if err = ginCtx.ShouldBindBodyWithJSON(&books); err != nil {
		s.log.Error().Err(err).Msg("parse body failed")
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Println(books)
	uidInt, err := strconv.Atoi(uid)
	if err != nil {
		s.log.Error().Err(err).Msg("parse uid from str to int failed")
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err = s.DB.SaveBooks(books, uidInt); err != nil {
		s.log.Error().Err(err).Msg("save books failed")
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	mes := fmt.Sprintf("Was saved %d books", len(books))
	ginCtx.String(http.StatusOK, mes)
}

func (s *Server) GetAllBooks(ginCtx *gin.Context) {
	token := ginCtx.GetHeader("Authorization")
	_, err := getUID(token)
	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	books, err := s.DB.GetAllBooks()
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, books)
}

func (s *Server) GetBooksByUser(ginCtx *gin.Context) {
	token := ginCtx.GetHeader("Authorization")
	uIDStr, err := getUID(token)
	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	uID, err := strconv.Atoi(uIDStr)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	books, err := s.DB.GetBooksByUser(uID)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, books)
}

func (s *Server) GetUserHandler(ginCtx *gin.Context) {
	param := ginCtx.Query("uid")
	log.Println("Param from url - " + param)
	uid, err := strconv.Atoi(param)
	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"error": "invalid argument"})
		return
	}
	log.Printf("UID - %v", uid)
	user, err := s.DB.GetUser(uid)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ginCtx.JSON(http.StatusOK, user)
}

func (s *Server) DeleteBook(ginCtx *gin.Context) {
	token := ginCtx.GetHeader("Authorization")
	_, err := getUID(token)
	if err != nil {
		ginCtx.JSON(http.StatusBadRequest, gin.H{"message": "Bad auth token", "error": err.Error()})
		return
	}
	bid := ginCtx.Param("id")
	bIDInt, err := strconv.Atoi(bid)
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err = s.DB.SetDeleteStatus(bIDInt); err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.deleteChan <- bIDInt
	ginCtx.String(http.StatusOK, "Book was deleted")
}

func (s *Server) deleter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if len(s.deleteChan) == 5 { //nolint: gomnd // todo
				for i := 0; i < 5; i++ {
					<-s.deleteChan
				}
				if err := s.DB.DeleteBooks(); err != nil {
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
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenTimout)),
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

	token, err := jwt.ParseWithClaims(tokenStr, claim, func(_ *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", errors.New("invalid token")
	}

	return claim.UserID, nil
}
