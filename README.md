
# Psychro-Scanner

Psychro-Scanner is a network and vulnerability scanning tool that automates host discovery, port scanning, and service detection while storing results in a structured SQLite database. The tool offers flexible scanning options, including the ability to load previously generated Nmap XML files into the database for analysis.

Features
 - Discovery Scans: Supports ping-only, full discovery, and TCP/UDP port scans.
 - Service Detection: Detects running services on open ports.
 - Database Integration: Stores scan results in an SQLite database, including IP addresses, ports, and service details.
 - Command-Line Interaction: Interact with the database to list services, search for specific services, and view CPE mappings.
 - Future Feature: CPE and CVE Support (coming soon) for enhanced vulnerability detection.

Setup Instructions
 - Prerequisites
   - Go 1.16 or later
   - Nmap installed and in the system path
   - SQLite3 (installed automatically through Go packages)

# Discovery and Profiling Scanner

## **Table of Contents**

* [Usage](#usage)
* [Flags](#flags)
* [Output Directory Structure](#output-directory-structure)
* [Customization](#customization)
* [Database Functionality](#database-functionality)
* [Extending Functionality](#extending-functionality)

---

## **Usage**

Dependencies

go install github.com/charmbracelet/bubbletea@latest
Nmap 

To compile and run the program:

1. **Compile the Program**

   ```bash
   go mod init scanner
   go mod tidy
   ```

   ```bash
   go build -o psychro_scanner main.go nmap.go output.go utils.go
   ```



2. **Run the Program**

   ```bash
   ./psychro_scanner -f targets.txt -v --debug --min-rtt 100ms --max-rtt 500ms
   ```

   Replace `targets.txt` with your target file.

## **Flags**

The program accepts the following flags:

| Flag | Description |
|------|-------------|
| `-f` | Specifies the target file for scanning (e.g., targets.txt). |
| `-v` | Enables verbose mode to display additional runtime information. |
| `-debug` | Enables debug mode, displaying detailed information about command execution and progress. |
| `--ping` | Runs only the Discovery Ping Scan for fast identification of live hosts without port scans or DNS lookups. |
| `--fulldisco` | Runs both the Discovery Ping Scan and the standard Discovery Scan for higher accuracy in identifying hosts. |
| `--min-rtt` | Sets the minimum RTT timeout for Nmap (e.g., --min-rtt 100ms). |
| `--max-rtt` | Sets the maximum RTT timeout for Nmap (e.g., --max-rtt 500ms). |
| `--load <path>` | Load a previously generated Nmap XML file into the database for analysis. |

### Flag Details
- `--ping`: Runs only the Discovery Ping Scan using ICMP, TCP, and UDP probes to identify live hosts quickly. Results are saved in `ips_active_ping.txt`.
- `--fulldisco`: Enables comprehensive discovery, starting with the Ping Scan, followed by the Discovery Scan on IPs identified by the Ping Scan for enhanced accuracy.

## **Output Directory Structure**

The program automatically creates an organized directory structure for each scan, named `Scan_[Timestamp]`. Each scan includes subdirectories for logs, data files, and Nmap outputs.

### **Example Directory Structure**

```plaintext
Scan_YYYYMMDD_HHMMSS/
│
├── logs/
│   ├── verbose_nmap_discovery_output.txt
│   ├── verbose_nmap_discovery_ping_output.txt
│   ├── verbose_nmap_tcp_port_discovery_output.txt
│   └── verbose_nmap_udp_port_discovery_output.txt
│
├── data/
│   ├── ips_active.txt           # List of active IPs discovered
│   ├── ips_active_ping.txt      # List of active IPs from Ping Discovery Scan
│   ├── ports_open_tcp.txt       # List of open TCP ports
│   └── ports_open_udp.txt       # List of open UDP ports
│
└── nmap_output/
    ├── discovery/
    │   ├── nmap_discovery_scan_results.nmap
    │   ├── nmap_discovery_scan_results.xml
    │   └── nmap_discovery_scan_results.gnmap
    │
    ├── tcp_port_discovery/
    │   ├── nmap_tcp_port_discovery_results.nmap
    │   ├── nmap_tcp_port_discovery_results.xml
    │   └── nmap_tcp_port_discovery_results.gnmap
    │
    ├── udp_port_discovery/
    │   ├── nmap_udp_port_discovery_results.nmap
    │   ├── nmap_udp_port_discovery_results.xml
    │   └── nmap_udp_port_discovery_results.gnmap
    │
    └── service_detection/
        ├── nmap_service_detection_results.nmap
        ├── nmap_service_detection_results.xml
        └── nmap_service_detection_results.gnmap
```

* **Logs**: Stores verbose outputs for each scan phase.
* **Data**: Contains lists of active IPs and open TCP/UDP ports.
* **Nmap Output**: Organized into separate folders for discovery, TCP, UDP, and service detection scans.

## **Customization**

### **Modifying Output Directory Structure and File Names**

Directory names and file paths can be customized within the program. These variables are set in the `nmap.go` and `output.go` files. To customize:

1. Open `main.go`, `nmap.go`, or `output.go`.
2. Modify directory paths and file name variables in the respective `InitializeFilePaths` functions:
   - **Nmap Output**: Adjust paths in `nmapInitializeFilePaths` within `nmap.go`.
   - **Data Output**: Modify paths in `outputInitializeFilePath` within `output.go`.
3. Recompile the program.

### **Adjusting Scan Parameters**

Nmap command parameters can be edited in `nmap.go` functions for each scan phase:

* **Discovery Scan**: `runDiscoveryScan`
* **TCP Port Discovery**: `runTCPPortDiscoveryScan`
* **UDP Port Discovery**: `runUDPPortDiscoveryScan`
* **Service Detection**: `runServiceDetectionScan`

## **Database Functionality**

Psychro-Scanner includes database functionality for storing scan results. After each scan, results are stored in an SQLite database (`vuln_scanner.db`), structured with two main tables:

- **services**: Contains details for each discovered service, including IP, port, protocol, and version.
- **cpe_mappings**: Maps services to corresponding CPE identifiers (CPE support coming soon).

### Database Interaction

After running a scan or loading an XML file with `--load`, use the CLI to interact with the database:

1. **List Services**: Display all services in the database.
2. **Search Services**: Search by service name.
3. **View CPEs**: View associated CPE mappings for a service.

## **Extending Functionality**

This program is designed with modularity in mind, making it straightforward to add new features, scan types, or file outputs.

When building on this program, keep the following principles in mind:

- **Modularity**: Place scan functions in `nmap.go`, data handling in `output.go`, and initialization in `main.go`.
- **Flags**: Add new command-line flags by extending the `flag` library options in `main.go`.
- **Path Configuration**: Define any new file paths in `nmapInitializeFilePaths` or `outputInitializeFilePaths`.

---
