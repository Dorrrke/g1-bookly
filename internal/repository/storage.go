package repository

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Dorrrke/g1-bookly/internal/domain/models"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

type DBStorage struct {
	conn *pgx.Conn
}

func NewDB(conn *pgx.Conn) (DBStorage, error) {
	return DBStorage{
		conn: conn,
	}, nil
}

func (db *DBStorage) GetUserByLogin(login string) (models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := db.conn.QueryRow(ctx, "SELECT * FROM users WHERE login = $1", login)
	var user models.User
	if err := row.Scan(&user.UID, &user.Name, &user.Login, &user.Password); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (db *DBStorage) GetAllUsers() ([]models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := db.conn.Query(ctx, "SELECT name, login, password FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []models.User
	for rows.Next() {
		var user models.User
		if err := rows.Scan(&user.Name, &user.Login, &user.Password); err != nil {
			return nil, err
		}
		user.Name = strings.TrimSpace(user.Name)
		user.Login = strings.TrimSpace(user.Login)
		user.Password = strings.TrimSpace(user.Password)
		users = append(users, user)
	}
	return users, nil
}

func (db *DBStorage) GetUser(uid int) (models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := db.conn.QueryRow(ctx, "SELECT name, login, password FROM users WHERE uid=$1", uid)
	var user models.User
	if err := row.Scan(&user.Name, &user.Login, &user.Password); err != nil {
		return models.User{}, err
	}
	return user, nil
}

func (db *DBStorage) InsertUser(user models.User) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := db.conn.QueryRow(ctx, "INSERT INTO users (name, login, password) VALUES ($1, $2, $3) RETURNING uid", user.Name, user.Login, user.Password)
	var uID int
	if err := row.Scan(&uID); err != nil {
		return -1, err
	}
	return uID, nil
}

func (db *DBStorage) DeleteUser(uid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := db.conn.Exec(ctx, "DELETE FROM users WHERE uid=$1", uid)
	if err != nil {
		return fmt.Errorf("delete user failed: %w", err)
	}
	return nil
}

func (db *DBStorage) SaveBook(book models.Book) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := db.conn.Exec(ctx, "INSERT INTO books (lable, author, uid) VALUES ($1, $2, $3)", book.Lable, book.Author, book.UID)
	if err != nil {
		return err
	}
	return nil
}

func (db *DBStorage) SaveBooks(books []models.Book, uid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("create transaction failed: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil {
			log.Fatal(err.Error())
		}
	}()
	if _, err := tx.Prepare(ctx, "insert book", "INSERT INTO books (lable, author, uid) VALUES ($1, $2, $3)"); err != nil {
		return fmt.Errorf("create prepare sql str failed: %w", err)
	}
	for _, book := range books {
		if _, err := tx.Exec(ctx, "insert book", book.Lable, book.Author, uid); err != nil {
			return fmt.Errorf("failed insert book: %w", err)
		}
	}
	return tx.Commit(ctx)
}

func (db *DBStorage) GetAllBooks() ([]models.Book, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := db.conn.Query(ctx, "SELECT bid, lable, author, uid FROM books")
	if err != nil {
		return nil, err
	}
	var books []models.Book
	for rows.Next() {
		var book models.Book
		if err := rows.Scan(&book.BID, &book.Lable, &book.Author, &book.UID); err != nil {
			return nil, err
		}
		books = append(books, book)
	}
	return books, nil
}

func (db *DBStorage) GetBooksByUser(uId int) ([]models.Book, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := db.conn.Query(ctx, "SELECT lable, author FROM books WHERE uid=$1", uId)
	if err != nil {
		return nil, err
	}
	var books []models.Book
	for rows.Next() {
		var book models.Book
		if err := rows.Scan(&book.Lable, &book.Author); err != nil {
			return nil, err
		}
		books = append(books, book)
	}
	return books, nil
}

func (db *DBStorage) SetDeleteStatus(bid int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.conn.Exec(ctx, "UPDATE books SET delete = true WHERE bid = $1", bid); err != nil {
		return fmt.Errorf("update delete status failed: %w", err)
	}
	return nil
}

func (db *DBStorage) DeleteBooks() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := db.conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("create transaction failed: %w", err)
	}
	defer func() {
		if err := tx.Rollback(ctx); err != nil {
			log.Fatal(err.Error())
		}
	}()
	if _, err := tx.Prepare(ctx, "delete book", "DELETE FROM books WHERE delete = true"); err != nil {
		return fmt.Errorf("create prepare sql str failed: %w", err)
	}
	if _, err := tx.Exec(ctx, "delete book"); err != nil {
		return fmt.Errorf("failed delete book: %w", err)
	}
	return tx.Commit(ctx)
}

func Migrations(dbAddr, migrationsPath string, zlog *zerolog.Logger) error {
	migratePath := fmt.Sprintf("file://%s", migrationsPath)
	m, err := migrate.New(migratePath, dbAddr)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			zlog.Debug().Msg("No migrations apply")
			return nil
		}
		return err
	}
	zlog.Debug().Msg("Migrate complete")
	return nil
}
