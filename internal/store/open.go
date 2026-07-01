package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(dsn string) (*Store, error) {
	driver, normalized, err := normalizeDSN(dsn)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, normalized)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	s := &Store{db: db}
	if err := s.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func normalizeDSN(dsn string) (driver string, normalized string, err error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		dsn = "vibesec.db"
	}
	lower := strings.ToLower(dsn)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return "pgx", dsn, nil
	}
	if strings.Contains(dsn, "://") {
		return "", "", fmt.Errorf("unsupported database DSN")
	}
	return "sqlite", "file:" + dsn + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", nil
}
