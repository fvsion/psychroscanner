package db

import (
    "database/sql"
    "encoding/xml"
    "fmt"
    "os"
)

// NmapService represents a service entry in the Nmap XML file
type NmapService struct {
    Name     string `xml:"name,attr"`
    Product  string `xml:"product,attr"`
    Version  string `xml:"version,attr"`
    CPE      string `xml:"cpe"`
    Protocol string `xml:"protocol,attr"`
    Port     int    `xml:"portid,attr"`
}

// Port represents a port entry associated with a service in Nmap XML
type Port struct {
    Service NmapService `xml:"service"`
}

// Address represents an address entry within a host in the Nmap XML file
type Address struct {
    Addr     string `xml:"addr,attr"`
    AddrType string `xml:"addrtype,attr"`
}

// Host represents a host entry in the Nmap XML file
type Host struct {
    Addresses []Address `xml:"address"`
    Ports     []Port    `xml:"ports>port"`
}

// NmapRun represents the top-level structure of the Nmap XML file
type NmapRun struct {
    Hosts []Host `xml:"host"`
}

// LoadNmapData loads services and CPEs from an Nmap XML file into the database
func LoadNmapData(db *sql.DB, filePath string) error {
    xmlFile, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("could not open XML file: %v", err)
    }
    defer xmlFile.Close()

    var nmapRun NmapRun
    decoder := xml.NewDecoder(xmlFile)
    if err := decoder.Decode(&nmapRun); err != nil {
        return fmt.Errorf("error decoding XML: %v", err)
    }

    for _, host := range nmapRun.Hosts {
        var ipAddress string
        for _, address := range host.Addresses {
            if address.AddrType == "ipv4" { // Using only IPv4 addresses; adjust as needed
                ipAddress = address.Addr
                break
            }
        }

        for _, port := range host.Ports {
            dbService := DBService{
                IP:          ipAddress,
                ServiceName: port.Service.Name,
                Product:     port.Service.Product,
                Version:     port.Service.Version,
                Protocol:    port.Service.Protocol,
                Port:        port.Service.Port,
            }

            // Insert service into the database
            serviceID, err := InsertService(db, dbService)
            if err != nil {
                fmt.Printf("Error inserting service: %v\n", err)
                continue
            }

            // Insert CPE mapping if available
            if port.Service.CPE != "" {
                if err := InsertCPEMapping(db, serviceID, port.Service.CPE); err != nil {
                    fmt.Printf("Error inserting CPE mapping: %v\n", err)
                }
            }
        }
    }

    fmt.Println("Nmap data loaded into database successfully.")
    return nil
}

