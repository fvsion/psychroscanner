package cpeGen

import (
    "encoding/xml"
    "fmt"
    "os"
    "strings"
    "scanner/database"
)

// Service represents each service entry in the XML file
type Service struct {
    Name     string `xml:"name,attr"`
    Product  string `xml:"product,attr"`
    Version  string `xml:"version,attr"`
    CPE      string `xml:"cpe"`
    DeviceType string `xml:"devicetype,attr"`
}

// Host represents each host in the XML file
type Host struct {
    Address string    `xml:"address>addr,attr"`
    Ports   []Service `xml:"ports>port>service"`
}

// NmapRun represents the top-level structure of the XML file
type NmapRun struct {
    Hosts []Host `xml:"host"`
}

// LoadServicesFromXML loads and parses the XML file
func LoadServicesFromXML(filePath string) ([]Host, error) {
    xmlFile, err := os.Open(filePath)
    if err != nil {
        return nil, fmt.Errorf("could not open XML file: %v", err)
    }
    defer xmlFile.Close()

    var nmapRun NmapRun
    decoder := xml.NewDecoder(xmlFile)
    if err := decoder.Decode(&nmapRun); err != nil {
        return nil, fmt.Errorf("error decoding XML: %v", err)
    }

    return nmapRun.Hosts, nil
}

// GenerateCPE generates a CPE string based on service information if none is provided
func GenerateCPE(service Service) string {
    if service.CPE != "" {
        return service.CPE
    }

    // Generate a CPE based on known CPE structure
    vendor := strings.ToLower(service.Name)
    product := strings.ToLower(service.Product)
    version := strings.ToLower(service.Version)

    return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

// GenerateCPEsForHosts generates CPEs for all hosts and their services
func GenerateCPEsForHosts(hosts []Host) {
    for _, host := range hosts {
        fmt.Printf("Host: %s\n", host.Address)
        for _, service := range host.Ports {
            cpe := GenerateCPE(service)
            fmt.Printf("Service: %s, Product: %s, Version: %s, CPE: %s\n", service.Name, service.Product, service.Version, cpe)
        }
        fmt.Println()
    }
}

