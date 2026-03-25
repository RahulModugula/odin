// Package userservice provides user management operations.
package userservice

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrUserNotFound is returned when a user cannot be found by the given criteria.
var ErrUserNotFound = errors.New("user not found")

// User represents a system user.
type User struct {
	ID    int64
	Name  string
	Email string
}

// Repository handles data persistence for users.
type Repository struct {
	db *sql.DB
}

// NewRepository creates a new user repository with the given database connection.
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// GetByID retrieves a user by their ID.
func (r *Repository) GetByID(ctx context.Context, id int64) (*User, error) {
	var u User
	err := r.db.QueryRowContext(
		ctx,
		"SELECT id, name, email FROM users WHERE id = $1",
		id,
	).Scan(&u.ID, &u.Name, &u.Email)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("GetByID %d: %w", id, ErrUserNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("GetByID %d: %w", id, err)
	}
	return &u, nil
}
