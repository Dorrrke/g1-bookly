package repository

import (
	"github.com/Dorrrke/g1-bookly/internal/domain/models"
)

type Repository struct {
	db map[int]models.User
}

func New() *Repository {
	db := make(map[int]models.User)
	return &Repository{
		db: db,
	}
}

func (repo *Repository) GetAllUsers() ([]models.User, error) {
	users := []models.User{}
	for _, user := range repo.db {
		users = append(users, user)
	}
	return users, nil
}
func (repo *Repository) GetUser(uid int) (models.User, error) {
	return repo.db[uid], nil
}
func (repo *Repository) InsertUser(user models.User) (int, error) {
	repo.db[user.UID] = user
	return user.UID, nil
}
func (repo *Repository) DeleteUser(uid int) error {
	delete(repo.db, uid)
	return nil
}
