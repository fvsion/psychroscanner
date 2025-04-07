package db

import (
    "database/sql"
    "fmt"
    "log"
    _ "github.com/mattn/go-sqlite3"
)

// dbPath defines the path to the SQLite database
const dbPath = "vuln_scanner.db"

// OpenDatabase opens a connection to the SQLite database
func OpenDatabase() (*sql.DB, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, fmt.Errorf("could not open database: %v", err)
    }
    return db, nil
}

// ListServices allows users to list all services in the database
func ListServices(db *sql.DB) {
    rows, err := db.Query("SELECT id, service_name, product, version, protocol, port FROM services")
    if err != nil {
        log.Fatalf("Error querying services: %v", err)
    }
    defer rows.Close()

    fmt.Println("ID | Service Name | Product | Version | Protocol | Port")
    fmt.Println("------------------------------------------------------")
    for rows.Next() {
        var id int
        var serviceName, product, version, protocol string
        var port int
        if err := rows.Scan(&id, &serviceName, &product, &version, &protocol, &port); err != nil {
            log.Fatalf("Error scanning row: %v", err)
        }
        fmt.Printf("%d | %s | %s | %s | %s | %d\n", id, serviceName, product, version, protocol, port)
    }
}

// ViewCPEs lists CPE mappings for a given service ID
func ViewCPEs(db *sql.DB, serviceID int) {
    query := `SELECT cpe FROM cpe_mappings WHERE service_id = ?`
    rows, err := db.Query(query, serviceID)
    if err != nil {
        log.Fatalf("Error querying CPE mappings: %v", err)
    }
    defer rows.Close()

    fmt.Printf("CPEs for Service ID %d:\n", serviceID)
    for rows.Next() {
        var cpe string
        if err := rows.Scan(&cpe); err != nil {
            log.Fatalf("Error scanning row: %v", err)
        }
        fmt.Println(cpe)
    }
}

// SearchService allows users to search for services by name or other attributes
func SearchService(db *sql.DB, serviceName string) {
    query := `SELECT id, service_name, product, version, protocol, port 
              FROM services WHERE service_name LIKE ?`
    rows, err := db.Query(query, "%"+serviceName+"%")
    if err != nil {
        log.Fatalf("Error querying services: %v", err)
    }
    defer rows.Close()

    fmt.Printf("Results for services matching '%s':\n", serviceName)
    for rows.Next() {
        var id int
        var name, product, version, protocol string
        var port int
        if err := rows.Scan(&id, &name, &product, &version, &protocol, &port); err != nil {
            log.Fatalf("Error scanning row: %v", err)
        }
        fmt.Printf("ID: %d, Service: %s, Product: %s, Version: %s, Protocol: %s, Port: %d\n", id, name, product, version, protocol, port)
    }
}
