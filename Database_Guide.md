
# Database Interaction Guide for Psychro-Scanner

Psychro-Scanner stores scan results in a structured SQLite database (`vuln_scanner.db`). This database includes information on discovered services, as well as mappings to potential vulnerabilities (coming soon). This guide explains how to interact with the database to view and analyze scan results.

---

## Table of Contents

* [Database Structure](#database-structure)
* [Database Tables Overview](#database-tables-overview)
* [Interactive Database Commands](#interactive-database-commands)
* [Examples](#examples)

---

## Database Structure

The Psychro-Scanner database (`vuln_scanner.db`) includes two main tables:

1. **services**: Contains details about detected services, including IP addresses, service names, products, versions, protocols, and ports.
2. **cpe_mappings**: Maps services to Common Platform Enumeration (CPE) identifiers. This feature enables future expansion to link services with known vulnerabilities (CVEs).

The database is created automatically when you run a scan or use the `--load` flag to import an Nmap XML file.

---

## Database Tables Overview

### `services` Table

Stores information about each service detected during a scan.

| Column         | Type    | Description                                    |
|----------------|---------|------------------------------------------------|
| `id`           | INTEGER | Primary key                                    |
| `ip`           | TEXT    | IP address of the service                      |
| `service_name` | TEXT    | Name of the service                            |
| `product`      | TEXT    | Product associated with the service            |
| `version`      | TEXT    | Version of the product                         |
| `protocol`     | TEXT    | Protocol (TCP/UDP)                             |
| `port`         | INTEGER | Port number where the service was detected     |

### `cpe_mappings` Table

Maps each service to CPE identifiers. The CPEs describe the platform and software details, making it easier to identify potential vulnerabilities.

| Column       | Type    | Description                                   |
|--------------|---------|-----------------------------------------------|
| `id`         | INTEGER | Primary key                                   |
| `service_id` | INTEGER | Foreign key linking to `services.id`          |
| `cpe`        | TEXT    | CPE identifier for the service                |

---

## Interactive Database Commands

After a scan completes or when using the `--load` option, you can use the command-line interface to interact with the database. You will see the following options:

1. **List All Services**: Displays all services currently stored in the database.
2. **Search for a Service**: Allows you to search for services by name.
3. **View CPEs for a Service**: Lists all CPE identifiers associated with a specific service.

### Command Details

1. **List All Services**: 
   - Shows a table of all detected services in the database, including IP, service name, product, version, protocol, and port.
   - Useful for reviewing what services were found on your network.

2. **Search for a Service**:
   - Prompts you to enter a service name to search.
   - Displays all services with names that match or contain the search term.

3. **View CPEs for a Service**:
   - Asks for a service ID to retrieve associated CPE mappings.
   - This can be used to view platform and software details (useful for vulnerability research in future updates).

---

## Examples

Here’s how to use each option in the interactive CLI:

### Example 1: Listing All Services

After choosing "1" to list all services, you’ll see a table with each service, displaying IP, service name, product, version, protocol, and port:

```plaintext
Database Interaction Menu:
1. List All Services
2. Search for a Service
3. View CPEs for a Service
4. Exit

Enter choice: 1

ID | IP          | Service Name | Product | Version | Protocol | Port
--------------------------------------------------------------
1  | 192.168.1.5 | http         | Apache  | 2.4.46  | tcp      | 80
2  | 192.168.1.5 | ssh          | OpenSSH | 7.9     | tcp      | 22
3  | 192.168.1.10| mysql        | MySQL   | 8.0.21  | tcp      | 3306
```

### Example 2: Searching for a Service

After selecting "2" to search for a service by name, type the name or part of the name of the service you’re looking for.

```plaintext
Enter service name to search: ssh

Results for services matching 'ssh':
ID: 2, Service: ssh, Product: OpenSSH, Version: 7.9, Protocol: tcp, Port: 22
```

### Example 3: Viewing CPEs for a Service

After choosing "3" to view CPEs, enter the ID of the service you want to examine.

```plaintext
Enter service ID to view CPEs: 2

CPEs for Service ID 2:
cpe:/a:openssh:openssh:7.9
```

---

## Future Enhancements

Future releases will include:

- **CVE Integration**: Directly linking CPEs to known vulnerabilities.
- **Automated Vulnerability Detection**: Real-time querying against vulnerability databases for identified CPEs.

---

Let me know if you need further customization or additional sections for this guide!
