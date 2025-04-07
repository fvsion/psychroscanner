package main

import (
    "encoding/xml"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
)

// Declare variables without initialization
var (
    // Data files
    activeIPsFile       string
    openTCPPortsFile    string
    openUDPPortsFile    string
    activePingIPsFile   string // New file for storing active IPs from Discovery Ping Scan
)

// InitializeFilePaths initializes the file paths after directories are created
func outputInitializeFilePaths(dataDir string) {
    activeIPsFile = getAbsPath(filepath.Join(dataDir, "ips_active.txt"))
    openTCPPortsFile = getAbsPath(filepath.Join(dataDir, "ports_open_tcp.txt"))
    openUDPPortsFile = getAbsPath(filepath.Join(dataDir, "ports_open_udp.txt"))
    activePingIPsFile = getAbsPath(filepath.Join(dataDir, "ips_active_ping.txt"))
}

// Structs for parsing Nmap XML

type NmapRun struct {
    XMLName xml.Name `xml:"nmaprun"`
    Hosts   []Host   `xml:"host"`
}

type Host struct {
    Status  Status    `xml:"status"`
    Address []Address `xml:"address"`
    Ports   Ports     `xml:"ports"`
}

type Status struct {
    State string `xml:"state,attr"`
}

type Address struct {
    Addr     string `xml:"addr,attr"`
    AddrType string `xml:"addrtype,attr"`
}

type Ports struct {
    Port []Port `xml:"port"`
}

type Port struct {
    Protocol string  `xml:"protocol,attr"`
    PortID   uint16  `xml:"portid,attr"`
    State    State   `xml:"state"`
    Service  Service `xml:"service"`
}

type State struct {
    State     string `xml:"state,attr"`
    Reason    string `xml:"reason,attr"`
    ReasonTTL string `xml:"reason_ttl,attr"`
}

type Service struct {
    Name string `xml:"name,attr"`
}

// Extract Active IPs from Default Discovery Scan
func extractActiveIPs() ([]string, error) {
    fmt.Println("Extracting active IP addresses from Discovery Scan...")
    xmlFilePath := discoveryOutputFile + ".xml"
    xmlFile, err := os.Open(xmlFilePath)
    if err != nil {
        return nil, err
    }
    defer xmlFile.Close()

    decoder := xml.NewDecoder(xmlFile)
    var nmapRun NmapRun
    if err := decoder.Decode(&nmapRun); err != nil {
        return nil, err
    }

    activeIPs := make([]string, 0)
    for _, host := range nmapRun.Hosts {
        if host.Status.State == "up" {
            for _, addr := range host.Address {
                if addr.AddrType == "ipv4" {
                    activeIPs = append(activeIPs, addr.Addr)
                    break
                }
            }
        }
    }

    // Remove duplicates
    ipSet := make(map[string]struct{})
    for _, ip := range activeIPs {
        ipSet[ip] = struct{}{}
    }
    uniqueIPs := make([]string, 0, len(ipSet))
    for ip := range ipSet {
        uniqueIPs = append(uniqueIPs, ip)
    }

    // Write active IPs to file
    err = ioutil.WriteFile(activeIPsFile, []byte(strings.Join(uniqueIPs, "\n")), 0644)
    if err != nil {
        return nil, err
    }

    fmt.Println("Active IPs discovered:", uniqueIPs)
    return uniqueIPs, nil
}

// Extract Active IPs from Discovery Ping Scan
func extractActiveIPsFromPingScan() ([]string, error) {
    fmt.Println("Extracting active IP addresses from Discovery Ping Scan...")
    xmlFilePath := discoveryPingOutputFile + ".xml"
    xmlFile, err := os.Open(xmlFilePath)
    if err != nil {
        return nil, err
    }
    defer xmlFile.Close()

    decoder := xml.NewDecoder(xmlFile)
    var nmapRun NmapRun
    if err := decoder.Decode(&nmapRun); err != nil {
        return nil, err
    }

    activeIPs := make([]string, 0)
    for _, host := range nmapRun.Hosts {
        if host.Status.State == "up" {
            for _, addr := range host.Address {
                if addr.AddrType == "ipv4" {
                    activeIPs = append(activeIPs, addr.Addr)
                    break
                }
            }
        }
    }

    // Remove duplicates
    ipSet := make(map[string]struct{})
    for _, ip := range activeIPs {
        ipSet[ip] = struct{}{}
    }
    uniqueIPs := make([]string, 0, len(ipSet))
    for ip := range ipSet {
        uniqueIPs = append(uniqueIPs, ip)
    }

    // Write active IPs to ips_active_ping.txt
    err = ioutil.WriteFile(activePingIPsFile, []byte(strings.Join(uniqueIPs, "\n")), 0644)
    if err != nil {
        return nil, err
    }

    fmt.Println("Active IPs from Discovery Ping Scan saved to", activePingIPsFile)
    return uniqueIPs, nil
}

// Extract Open Ports from Port Discovery Scans
func extractOpenPorts() ([]string, []string, error) {
    fmt.Println("Extracting open TCP ports from TCP port discovery scan...")
    openTCPPorts, err := extractOpenPortsFromScan(tcpPortDiscoveryOutputFile+".xml", "tcp")
    if err != nil {
        return nil, nil, err
    }

    fmt.Println("Extracting open UDP ports from UDP port discovery scan...")
    openUDPPorts, err := extractOpenPortsFromScan(udpPortDiscoveryOutputFile+".xml", "udp")
    if err != nil {
        return nil, nil, err
    }

    // Write open TCP ports to file
    err = ioutil.WriteFile(openTCPPortsFile, []byte(strings.Join(openTCPPorts, "\n")), 0644)
    if err != nil {
        return nil, nil, err
    }

    // Write open UDP ports to file
    err = ioutil.WriteFile(openUDPPortsFile, []byte(strings.Join(openUDPPorts, "\n")), 0644)
    if err != nil {
        return nil, nil, err
    }

    fmt.Println("Open TCP ports discovered:", openTCPPorts)
    fmt.Println("Open UDP ports discovered:", openUDPPorts)
    return openTCPPorts, openUDPPorts, nil
}

// Helper function to extract open ports from a scan
func extractOpenPortsFromScan(xmlFilePath string, protocol string) ([]string, error) {
    xmlFile, err := os.Open(xmlFilePath)
    if err != nil {
        return nil, err
    }
    defer xmlFile.Close()

    decoder := xml.NewDecoder(xmlFile)
    var nmapRun NmapRun
    if err := decoder.Decode(&nmapRun); err != nil {
        return nil, err
    }

    openPorts := make(map[uint16]struct{})
    for _, host := range nmapRun.Hosts {
        for _, port := range host.Ports.Port {
            if port.Protocol == protocol && port.State.State == "open" {
                openPorts[port.PortID] = struct{}{}
            }
        }
    }

    // Convert openPorts map to a sorted slice
    portList := make([]int, 0, len(openPorts))
    for port := range openPorts {
        portList = append(portList, int(port))
    }
    sort.Ints(portList)

    // Convert port numbers to strings
    portStrList := make([]string, 0, len(portList))
    for _, port := range portList {
        portStrList = append(portStrList, strconv.Itoa(port))
    }

    return portStrList, nil
}

