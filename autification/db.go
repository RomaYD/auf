package main

import (
    "database/sql"
    "fmt"
)

func initDatabase(db *sql.DB) error {
    query := `
    CREATE TABLE IF NOT EXISTS auf (
        guid UUID PRIMARY KEY,
        refresh TEXT NOT NULL,
		useragent TEXT NOT NULL,
		ip TEXT NOT NULL,

    );`
    _, err := db.Exec(query)
    if err != nil {
        return fmt.Errorf("ошибка создания таблицы: %v", err)
    }
    return nil
}