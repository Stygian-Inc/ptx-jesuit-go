package dns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type DoHResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// VerifyTXT queries DNS via DoH to verify if the hostname has a TXT record containing expected content
func VerifyTXT(hostname string, expectedContent string) (bool, error) {
	// Use Cloudflare DoH as a robust public resolver
	dohURL := "https://cloudflare-dns.com/dns-query"

	u, err := url.Parse(dohURL)
	if err != nil {
		return false, err
	}

	q := u.Query()
	q.Set("name", hostname)
	q.Set("type", "TXT")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, fmt.Errorf("DoH request failed with status code: %d", resp.StatusCode)
	}

	var dohResp DoHResponse
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return false, err
	}

	if dohResp.Status != 0 {
		// Status 0 is No Error.
		return false, nil
	}

	// Check answers
	for _, ans := range dohResp.Answer {
		if ans.Type == 16 { // TXT type is 16
			// data often comes as "quoted string" in JSON response
			// We check if it contains our expected hash
			if strings.Contains(ans.Data, expectedContent) {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetTXT returns all TXT records for a given hostname
func GetTXT(hostname string) ([]string, error) {
	dohURL := "https://cloudflare-dns.com/dns-query"

	u, err := url.Parse(dohURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("name", hostname)
	q.Set("type", "TXT")
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH request failed with status code: %d", resp.StatusCode)
	}

	var dohResp DoHResponse
	if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
		return nil, err
	}

	if dohResp.Status != 0 {
		return nil, nil
	}

	var txtRecords []string
	for _, ans := range dohResp.Answer {
		if ans.Type == 16 {
			// Strip quotes if present
			val := strings.Trim(ans.Data, "\"")
			txtRecords = append(txtRecords, val)
		}
	}

	return txtRecords, nil
}
