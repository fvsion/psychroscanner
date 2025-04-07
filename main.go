package main

import (
    "database/sql"
    "flag"
    "fmt"
    "log"
    "os"
    "path/filepath"
    "time"

    "scanner/db"
)

// Command-line flag variables
var (
    verboseMode   bool   // Enables verbose output if true
    debugMode     bool   // Enables debug output if true
    pingMode      bool   // Runs only the Discovery Ping Scan if true
    fulldiscoMode bool   // Runs full discovery with both Ping and original Discovery scans
    loadFile      string // Path to existing XML file to load into the database
    targetFile    string // Path to a file specifying scan targets
    minRTTTimeout string // Minimum RTT timeout for Nmap scans
    maxRTTTimeout string // Maximum RTT timeout for Nmap scans
    targets       []string
    nmapPath      = "nmap" // Path to the Nmap executable

    // Directory variables for output structure
    scanBaseDir         string
    logsDir             string
    dataDir             string
    nmapOutputDir       string
    discoveryPingDir    string
    discoveryOutputDir  string
    tcpPortDiscoveryDir string
    udpPortDiscoveryDir string
    serviceDetectionDir string
)

func main() {
    // Parse command-line options
    flag.BoolVar(&verboseMode, "v", false, "enable verbose mode")
    flag.BoolVar(&debugMode, "debug", false, "enable debug mode for additional output")
    flag.BoolVar(&pingMode, "ping", false, "run only the Discovery Ping Scan")
    flag.BoolVar(&fulldiscoMode, "fulldisco", false, "run full discovery with both Ping and original Discovery scans")
    flag.StringVar(&loadFile, "load", "", "specify an existing Nmap XML file to load into the database")
    flag.StringVar(&targetFile, "f", "", "specify target file")
    flag.StringVar(&minRTTTimeout, "min-rtt", "50ms", "set Nmap's --min-rtt-timeout value")
    flag.StringVar(&maxRTTTimeout, "max-rtt-timeout", "250ms", "set Nmap's --max-rtt-timeout value")
    flag.Parse()

    // Initialize output directories
    initializeDirectories()

    // Initialize database connection
    dbConn, err := db.OpenDatabase()
    if err != nil {
        log.Fatalf("Failed to open database: %v", err)
    }
    defer dbConn.Close()

    // Set up database tables if necessary
    if err := db.InitializeDB(dbConn); err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }

    // Load data from XML file if --load flag is provided
    if loadFile != "" {
        fmt.Printf("Loading data from XML file: %s\n", loadFile)
        if err := db.LoadNmapData(dbConn, loadFile); err != nil {
            log.Fatalf("Error loading data from XML file: %v", err)
        }
        fmt.Println("Data loaded into the database successfully.")
        interactWithDatabase(dbConn) // Start database interaction menu after loading
        return
    }

    // Parse target IPs or hostnames for scanning
    if err := parseTargets(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    var activeIPs []string

    // Run Ping-only scan or full discovery scan based on flags
    if pingMode {
        if err := runDiscoveryPingScan(targets); err != nil {
            fmt.Println("Error during Discovery Ping Scan:", err)
            os.Exit(1)
        }
        activeIPs, err = extractActiveIPsFromPingScan()
        if err != nil {
            fmt.Println("Error extracting active IPs from Discovery Ping Scan:", err)
            os.Exit(1)
        }

    } else if fulldiscoMode {
        // Run both Ping Scan and Discovery Scan in full discovery mode
        if err := runDiscoveryPingScan(targets); err != nil {
            fmt.Println("Error during Discovery Ping Scan:", err)
            os.Exit(1)
        }
        activeIPs, err = extractActiveIPsFromPingScan()
        if err != nil {
            fmt.Println("Error extracting active IPs from Discovery Ping Scan:", err)
            os.Exit(1)
        }
        if err := runDiscoveryScan(activeIPs); err != nil {
            fmt.Println("Error during discovery scan:", err)
            os.Exit(1)
        }
        activeIPs, err = extractActiveIPs()
        if err != nil {
            fmt.Println("Error extracting active IPs from Discovery Scan:", err)
            os.Exit(1)
        }

    } else {
        // Default: Run Discovery Scan
        if err := runDiscoveryScan(targets); err != nil {
            fmt.Println("Error during discovery scan:", err)
            os.Exit(1)
        }
        activeIPs, err = extractActiveIPs()
        if err != nil {
            fmt.Println("Error extracting active IPs:", err)
            os.Exit(1)
        }
    }

    // Exit if no active IPs were found
    if len(activeIPs) == 0 {
        fmt.Println("No active IP addresses found. Exiting.")
        os.Exit(0)
    }

    // Run TCP and UDP port discovery scans
    if err := runTCPPortDiscoveryScan(activeIPs); err != nil {
        fmt.Println("Error during TCP port discovery scan:", err)
        os.Exit(1)
    }
    if err := runUDPPortDiscoveryScan(activeIPs); err != nil {
        fmt.Println("Error during UDP port discovery scan:", err)
        os.Exit(1)
    }

    // Extract open TCP and UDP ports from scan results
    openTCPPorts, openUDPPorts, err := extractOpenPorts()
    if err != nil {
        fmt.Println("Error extracting open ports:", err)
        os.Exit(1)
    }
    if len(openTCPPorts) == 0 && len(openUDPPorts) == 0 {
        fmt.Println("No open ports found in port discovery scans. Exiting.")
        os.Exit(0)
    }

    // Run Service Detection Scan on open ports
    if err := runServiceDetectionScan(openTCPPorts, openUDPPorts, activeIPs); err != nil {
        fmt.Println("Error during service detection scan:", err)
        os.Exit(1)
    }

    // Load service detection results into the database
    serviceDetectionXMLPath := filepath.Join(serviceDetectionDir, "nmap_service_detection_results.xml")
    if err := db.LoadNmapData(dbConn, serviceDetectionXMLPath); err != nil {
        log.Fatalf("Error loading Nmap data into the database: %v", err)
    }

    fmt.Println("All scans completed successfully, and data loaded into the database.")
    interactWithDatabase(dbConn) // Start database interaction menu
}

// interactWithDatabase provides a command-line menu for user interaction with the database
func interactWithDatabase(dbConn *sql.DB) {
    for {
        fmt.Println("\nDatabase Interaction Menu:")
        fmt.Println("1. List All Services")
        fmt.Println("2. Search for a Service")
        fmt.Println("3. View CPEs for a Service")
        fmt.Println("4. Exit")

        var choice int
        fmt.Print("Enter choice: ")
        fmt.Scanf("%d", &choice)

        switch choice {
        case 1:
            db.ListServices(dbConn)
        case 2:
            fmt.Print("Enter service name to search: ")
            var name string
            fmt.Scan(&name)
            db.SearchService(dbConn, name)
        case 3:
            fmt.Print("Enter service ID to view CPEs: ")
            var serviceID int
            fmt.Scan(&serviceID)
            db.ViewCPEs(dbConn, serviceID)
        case 4:
            fmt.Println("Exiting database interaction.")
            return
        default:
            fmt.Println("Invalid choice. Please try again.")
        }
    }
}

// initializeDirectories sets up the directory structure for scan results
func initializeDirectories() {
    timestamp := time.Now().Format("20060102_150405")
    scanBaseDir = fmt.Sprintf("Scan_%s", timestamp)

    logsDir = filepath.Join(scanBaseDir, "logs")
    dataDir = filepath.Join(scanBaseDir, "data")
    nmapOutputDir = filepath.Join(scanBaseDir, "nmap_output")
    discoveryOutputDir = filepath.Join(nmapOutputDir, "discovery")
    tcpPortDiscoveryDir = filepath.Join(nmapOutputDir, "tcp_port_discovery")
    udpPortDiscoveryDir = filepath.Join(nmapOutputDir, "udp_port_discovery")
    serviceDetectionDir = filepath.Join(nmapOutputDir, "service_detection")
    discoveryPingDir = filepath.Join(nmapOutputDir, "discovery_ping")

    dirs := []string{
        logsDir, dataDir, discoveryOutputDir, tcpPortDiscoveryDir,
        udpPortDiscoveryDir, serviceDetectionDir, discoveryPingDir,
    }

    for _, dir := range dirs {
        if err := os.MkdirAll(dir, 0755); err != nil {
            fmt.Printf("Error creating directory %s: %v\n", dir, err)
            os.Exit(1)
        }
    }

    nmapInitializeFilePaths(
        discoveryPingDir, discoveryOutputDir, tcpPortDiscoveryDir,
        udpPortDiscoveryDir, serviceDetectionDir, logsDir,
    )

    outputInitializeFilePaths(dataDir)
}

// getAbsPath converts a relative path to an absolute path
func getAbsPath(path string) string {
    absPath, err := filepath.Abs(path)
    if err != nil {
        fmt.Printf("Error getting absolute path for %s: %v\n", path, err)
        os.Exit(1)
    }
    return absPath
}
