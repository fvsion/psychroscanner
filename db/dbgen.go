package db

import (
    "database/sql"
    "fmt"
)

// DBService struct represents a database service entry
type DBService struct {
    IP		string
    ServiceName string
    Product     string
    Version     string
    Protocol    string
    Port        int
}

// InitializeDB initializes tables in the provided database connection
func InitializeDB(db *sql.DB) error {
    createTablesSQL := `
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT,
        service_name TEXT NOT NULL,
        product TEXT,
        version TEXT,
        protocol TEXT,
        port INTEGER
    );

    CREATE TABLE IF NOT EXISTS cpe_mappings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_id INTEGER,
        cpe TEXT,
        FOREIGN KEY (service_id) REFERENCES services(id)
    );
    `
    if _, err := db.Exec(createTablesSQL); err != nil {
        return fmt.Errorf("error creating tables: %v", err)
    }

    return nil
}

// InsertService inserts a new DBService entry into the database
func InsertService(db *sql.DB, service DBService) (int64, error) {
    query := `INSERT INTO services (ip, service_name, product, version, protocol, port) VALUES (?, ?, ?, ?, ?, ?)`
    result, err := db.Exec(query, service.IP, service.ServiceName, service.Product, service.Version, service.Protocol, service.Port)
    if err != nil {
        return 0, fmt.Errorf("error inserting service: %v", err)
    }
    return result.LastInsertId()
}

// InsertCPEMapping inserts a CPE mapping for a given service ID
func InsertCPEMapping(db *sql.DB, serviceID int64, cpe string) error {
    query := `INSERT INTO cpe_mappings (service_id, cpe) VALUES (?, ?)`
    if _, err := db.Exec(query, serviceID, cpe); err != nil {
        return fmt.Errorf("error inserting CPE mapping: %v", err)
    }
    return nil
}
