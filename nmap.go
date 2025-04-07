package main

import (
    "fmt"
    "path/filepath"
    "strings"
)

// Declare variables without initialization
var (
    // Ping Discovery scan files
    discoveryPingOutputFile    string
    discoveryPingVerbose       string

    // Discovery scan files
    discoveryOutputFile string
    discoveryVerbose    string

    // TCP port discovery scan files
    tcpPortDiscoveryOutputFile string
    tcpPortDiscoveryVerbose    string

    // UDP port discovery scan files
    udpPortDiscoveryOutputFile string
    udpPortDiscoveryVerbose    string

    // Service detection scan files
    serviceDetectionOutputFile string
    serviceDetectionVerbose    string
)

// InitializeFilePaths initializes the file paths after directories are created
func nmapInitializeFilePaths(
    discoveryPingDir string,
    discoveryOutputDir string,
    tcpPortDiscoveryDir string,
    udpPortDiscoveryDir string,
    serviceDetectionDir string,
    logsDir string,
) {
    // Ping Discovery Scan files
    discoveryPingOutputFile = getAbsPath(filepath.Join(discoveryPingDir, "nmap_discovery_ping_scan_results"))
    discoveryPingVerbose = getAbsPath(filepath.Join(logsDir, "verbose_nmap_discovery_ping_output.txt"))

    // Discovery scan files
    discoveryOutputFile = getAbsPath(filepath.Join(discoveryOutputDir, "nmap_discovery_scan_results"))
    discoveryVerbose = getAbsPath(filepath.Join(logsDir, "verbose_nmap_discovery_output.txt"))

    // TCP port discovery scan files
    tcpPortDiscoveryOutputFile = getAbsPath(filepath.Join(tcpPortDiscoveryDir, "nmap_tcp_port_discovery_results"))
    tcpPortDiscoveryVerbose = getAbsPath(filepath.Join(logsDir, "verbose_nmap_tcp_port_discovery_output.txt"))

    // UDP port discovery scan files
    udpPortDiscoveryOutputFile = getAbsPath(filepath.Join(udpPortDiscoveryDir, "nmap_udp_port_discovery_results"))
    udpPortDiscoveryVerbose = getAbsPath(filepath.Join(logsDir, "verbose_nmap_udp_port_discovery_output.txt"))

    // Service detection scan files
    serviceDetectionOutputFile = getAbsPath(filepath.Join(serviceDetectionDir, "nmap_service_detection_results"))
    serviceDetectionVerbose = getAbsPath(filepath.Join(logsDir, "verbose_nmap_service_detection_output.txt"))
}

// runDiscoveryPingScan performs the Discovery Ping Scan
func runDiscoveryPingScan(targets []string) error {
    fmt.Println("Starting Discovery Ping Scan...")

    pingScanArgs := []string{
        nmapPath, "-sn", "-vvv", "--max-rtt-timeout", "100ms", "--open", "--host-timeout", "1m",
	"--max-scan-delay", "40ms",
 	"--min-hostgroup", "256", "--max-retries", "0", "-PE", "-PP",
        "-PS21,22,25,445,138,80,443,8080",
        "-PA21,25", "-PU40100,161",
        "--disable-arp-ping",
        "-n",
        "-oA", discoveryPingOutputFile,
    }
    pingScanArgs = append(pingScanArgs, targets...)

    if verboseMode {
        fmt.Println("Running Discovery Ping Scan with the following command:")
        fmt.Println(strings.Join(pingScanArgs, " "))
    }

    return runCommand(pingScanArgs, "Discovery Ping Scan in progress...", discoveryPingVerbose)
}

func runDiscoveryScan(targets []string) error {
    fmt.Println("Starting Nmap Discovery Scan...")

    nmapDiscoveryArgs := []string{
        nmapPath, "-Pn", "-sT", "-sU", "-vvv", "--stats-every", "15s",
        "--min-rate", "500", "--max-rate", "1000", "--max-retries", "0",
        "--host-timeout", "30m", "--min-parallelism", "10", "--max-parallelism", "150",
        "--initial-rtt-timeout", "150ms", "--min-rtt-timeout", minRTTTimeout, "--max-rtt-timeout", maxRTTTimeout,
        "--max-scan-delay", "200ms",
        "-p", "T:22,80,443,445,1433,1521,2049,3306,5432,5984,6379,8080,8443," +
             "U:53,123,161,500,1434", "--reason",
        "-oA", discoveryOutputFile,
    }

    nmapDiscoveryArgs = append(nmapDiscoveryArgs, targets...)

    if verboseMode {
        fmt.Println("Running Nmap Discovery Scan with the following command:")
        fmt.Println(strings.Join(nmapDiscoveryArgs, " "))
    }

    return runCommand(nmapDiscoveryArgs, "Nmap Discovery Scan in progress...", discoveryVerbose)
}

func runTCPPortDiscoveryScan(activeIPs []string) error {
    fmt.Println("Starting full TCP port discovery scan on active IPs...")
    tcpPortDiscoveryArgs := []string{
        nmapPath, "-Pn", "-sT", "-vvv", "--stats-every", "15s",
        "-p-", "--min-rate", "800", "--max-rate", "1500", "--max-retries", "0",
        "--host-timeout", "30m", "--min-parallelism", "20", "--max-parallelism", "200",
        "--initial-rtt-timeout", "100ms", "--min-rtt-timeout", minRTTTimeout, "--max-rtt-timeout", maxRTTTimeout,
        "--max-scan-delay", "100ms", "--reason", "-oA", tcpPortDiscoveryOutputFile,
    }
    tcpPortDiscoveryArgs = append(tcpPortDiscoveryArgs, activeIPs...)

    if verboseMode {
        fmt.Println("Running TCP port discovery scan with the following command:")
        fmt.Println(strings.Join(tcpPortDiscoveryArgs, " "))
	fmt.Println("Discovery output file path:", tcpPortDiscoveryOutputFile)
    }

    return runCommand(tcpPortDiscoveryArgs, "TCP port discovery scan in progress...", tcpPortDiscoveryVerbose)
}

func runUDPPortDiscoveryScan(activeIPs []string) error {
    fmt.Println("Starting UDP port discovery scan on active IPs...")
    udpPortDiscoveryArgs := []string{
        nmapPath, "-Pn", "-sU", "-vvv", "--stats-every", "15s",
        "--top-ports", "1000", "--min-rate", "500", "--max-rate", "1000", "--max-retries", "2",
        "--host-timeout", "30m", "--min-parallelism", "10", "--max-parallelism", "100",
        "--initial-rtt-timeout", "300ms", "--min-rtt-timeout", minRTTTimeout, "--max-rtt-timeout", maxRTTTimeout,
        "--max-scan-delay", "500ms", "--reason", "-oA", udpPortDiscoveryOutputFile,
    }
    udpPortDiscoveryArgs = append(udpPortDiscoveryArgs, activeIPs...)

    if verboseMode {
        fmt.Println("Running UDP port discovery scan with the following command:")
        fmt.Println(strings.Join(udpPortDiscoveryArgs, " "))
	fmt.Println("Discovery output file path:", udpPortDiscoveryOutputFile)
    }

    return runCommand(udpPortDiscoveryArgs, "UDP port discovery scan in progress...", udpPortDiscoveryVerbose)
}

func runServiceDetectionScan(openTCPPorts []string, openUDPPorts []string, activeIPs []string) error {
    fmt.Println("Starting service detection scan on open ports...")

    var portsArg string
    if len(openTCPPorts) > 0 && len(openUDPPorts) > 0 {
        portsArg = fmt.Sprintf("T:%s,U:%s", strings.Join(openTCPPorts, ","), strings.Join(openUDPPorts, ","))
    } else if len(openTCPPorts) > 0 {
        portsArg = fmt.Sprintf("T:%s", strings.Join(openTCPPorts, ","))
    } else if len(openUDPPorts) > 0 {
        portsArg = fmt.Sprintf("U:%s", strings.Join(openUDPPorts, ","))
    } else {
        fmt.Println("No open ports to scan for service detection.")
        return nil
    }

    serviceDetectionArgs := []string{
        nmapPath, "-Pn", "-sV", "-vvv", "--stats-every", "15s",
        "-p", portsArg, "--version-intensity", "3", "--reason", "-oA", serviceDetectionOutputFile,
    }
    serviceDetectionArgs = append(serviceDetectionArgs, activeIPs...)

    if verboseMode {
        fmt.Println("Running service detection scan with the following command:")
        fmt.Println(strings.Join(serviceDetectionArgs, " "))
	fmt.Println("Discovery output file path:", serviceDetectionOutputFile)
    }

    return runCommand(serviceDetectionArgs, "Service detection scan in progress...", serviceDetectionVerbose)
}

