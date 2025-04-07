package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "time"
)

// Configuration struct for reading the config file
type Config struct {
    NVDAPIKey string `json:"nvd_api_key"`
}

const nvdAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cves/1.0"

// NVDResponse represents the structure of the NVD API response
type NVDResponse struct {
    Result struct {
        CVEItems []struct {
            CVE struct {
                CVEDataMeta struct {
                    ID string `json:"ID"`
                } `json:"cveDataMeta"`
                Description struct {
                    DescriptionData []struct {
                        Value string `json:"value"`
                    } `json:"descriptionData"`
                } `json:"description"`
            } `json:"cve"`
        } `json:"CVE_Items"`
    } `json:"result"`
}

// loadConfig loads the API key from the config.json file
func loadConfig() (*Config, error) {
    configFile, err := os.Open("config.json")
    if err != nil {
        return nil, fmt.Errorf("could not open config.json: %v", err)
    }
    defer configFile.Close()

    var config Config
    decoder := json.NewDecoder(configFile)
    if err := decoder.Decode(&config); err != nil {
        return nil, fmt.Errorf("error decoding config.json: %v", err)
    }

    return &config, nil
}

// queryNVDAPI queries the NVD API with a specified CPE or keyword
func queryNVDAPI(query, apiKey string) (*NVDResponse, error) {
    url := fmt.Sprintf("%s?cpeMatchString=%s&apiKey=%s", nvdAPIBaseURL, query, apiKey)
    client := &http.Client{Timeout: 10 * time.Second}

    resp, err := client.Get(url)
    if err != nil {
        return nil, fmt.Errorf("error querying NVD API: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("NVD API returned status code %d", resp.StatusCode)
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("error reading response body: %v", err)
    }

    var nvdResponse NVDResponse
    if err := json.Unmarshal(body, &nvdResponse); err != nil {
        return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
    }

    return &nvdResponse, nil
}

// parseVulnerabilities parses and displays CVEs from the NVD response
func parseVulnerabilities(nvdResponse *NVDResponse) {
    for _, item := range nvdResponse.Result.CVEItems {
        cveID := item.CVE.CVEDataMeta.ID
        description := item.CVE.Description.DescriptionData[0].Value
        fmt.Printf("CVE: %s\nDescription: %s\n\n", cveID, description)
    }
}

func main() {
    // Load the API key from config.json
    config, err := loadConfig()
    if err != nil {
        fmt.Println("Error loading config:", err)
        return
    }

    // Example CPE for testing
    query := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    nvdResponse, err := queryNVDAPI(query, config.NVDAPIKey)
    if err != nil {
        fmt.Println("Error querying NVD API:", err)
        return
    }

    parseVulnerabilities(nvdResponse)
}

