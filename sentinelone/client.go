package sentinelone

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

type SentinelOneClient struct {
	BaseURL    string
	HTTPClient *http.Client
	APIToken   string
}

type HTTPError struct {
	Status  int
	Message string
	Body    string
}

func (he *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d %s: %s", he.Status, he.Message, he.Body)
}

type s1APIError struct {
	Errors []struct {
		Code   int     `json:"code"`
		Title  string  `json:"title"`
		Detail *string `json:"detail"`
	} `json:"errors"`
}

func parseS1APIError(body []byte) *s1APIError {
	var s s1APIError
	if err := json.Unmarshal(body, &s); err != nil {
		return nil
	}
	if len(s.Errors) == 0 {
		return nil
	}
	return &s
}

func makeAuthExpiredError(rawBody string) error {
	help := `
Authentication failed (expired or invalid API token).

How to refresh your credentials:
  1) Generate a new API token in the SentinelOne Console (User → API Tokens).
  2a) If you use environment variables export SENTINELONE_API_TOKEN="<NEW_TOKEN>" then re-run your query; OR
  2b) If you use a Steampipe connection file (e.g., ~/.steampipe/config/sentinelone.spc):
        connection "sentinelone" {
          plugin     = "sentinelone"
          client_id  = "<YOUR_TENANT>"
          api_token = "<NEW_TOKEN>"
        }
      then reload Steampipe.

Tip: ensure SENTINELONE_CLIENT_ID matches your tenant subdomain
(e.g., "acme" if the URL is https://acme.sentinelone.net).

Raw API response (for debugging):
`
	return fmt.Errorf("%s%s", strings.TrimSpace(help), "\n"+strings.TrimSpace(rawBody))
}

// BuildURL constructs the full URL for SentinelOne based on the path and parameters
func (c *SentinelOneClient) BuildURL(path string, params map[string]string) (string, error) {
	base := fmt.Sprintf("https://%s.sentinelone.net", c.BaseURL)

	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("invalid tenant URL %q: %w", base, err)
	}
	u.Path = path
	if len(params) > 0 {
		q := u.Query()
		for k, v := range params {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	return u.String(), nil
}

// Get sends a GET request and returns the response body
func (c *SentinelOneClient) Get(fullURL string) ([]byte, error) {
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("ApiToken %s", c.APIToken))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Steampipe/SentinelOne")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Specific handling for 401 (expired/invalid token)
	if resp.StatusCode == http.StatusUnauthorized {
		if parsed := parseS1APIError(body); parsed != nil {
			for _, e := range parsed.Errors {
				if e.Code == 4010010 || strings.EqualFold(e.Title, "Authentication Failed") {
					return nil, makeAuthExpiredError(string(body))
				}
			}
		}
		return nil, makeAuthExpiredError(string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{
			Status:  resp.StatusCode,
			Message: resp.Status,
			Body:    string(body),
		}
	}
	return body, nil
}

// Fetch unprocessed data from the API with pagination, stops early if the SQL LIMIT is hit.
// Fetching all data in a single call becomes extremely slow once the dataset exceeds ~10,000 records.
// The SentinelOne API enforces a maximum page size of 1,000.
func (t *SentinelOneClient) fetchPaginatedData(
	ctx context.Context,
	d *plugin.QueryData,
	endpoint string,
	limitPerPage int,
) ([]interface{}, map[string]interface{}, []interface{}, error) {
	var (
		allData        []interface{}
		lastPagination map[string]interface{}
		lastErrors     []interface{}
		cursor         string
	)

	var totalLimit int
	if d.QueryContext.Limit != nil {
		totalLimit = int(*d.QueryContext.Limit)
	}

outer:
	for {
		params := map[string]string{
			"limit": fmt.Sprintf("%d", limitPerPage),
		}
		if cursor != "" {
			params["cursor"] = cursor
		}

		fullURL, err := t.BuildURL(endpoint, params)
		if err != nil {
			return nil, nil, nil, err
		}
		body, err := t.Get(fullURL)
		if err != nil {
			return nil, nil, nil, err
		}

		var resp struct {
			Data       []interface{}          `json:"data"`
			Pagination map[string]interface{} `json:"pagination"`
			Errors     []interface{}          `json:"errors"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
		}

		for _, item := range resp.Data {
			allData = append(allData, item)
			if totalLimit > 0 && len(allData) >= totalLimit {
				lastPagination = resp.Pagination
				lastErrors = resp.Errors
				break outer
			}
		}
		lastPagination = resp.Pagination
		lastErrors = resp.Errors

		nextCursor, _ := resp.Pagination["nextCursor"].(string)
		if nextCursor == "" || nextCursor == cursor {
			break
		}
		cursor = nextCursor
	}

	return allData, lastPagination, lastErrors, nil
}

// authTransport injects the Authorization header into every request
type authTransport struct {
	underlying http.RoundTripper
	token      string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", fmt.Sprintf("ApiToken %s", t.token))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Steampipe/SentinelOne")
	return t.underlying.RoundTrip(req)
}

// Connect initializes the client by reading the tenant ID and token from config or environment variables
func Connect(_ context.Context, d *plugin.QueryData) (*SentinelOneClient, error) {
	const cacheKey = "sentinelone_client"
	if cached, ok := d.ConnectionManager.Cache.Get(cacheKey); ok {
		return cached.(*SentinelOneClient), nil
	}

	cfg := GetConfig(d.Connection)

	tenant := os.Getenv("SENTINELONE_CLIENT_ID")
	if cfg.ClientID != nil {
		tenant = *cfg.ClientID
	}
	if tenant == "" {
		return nil, errors.New("SENTINELONE_CLIENT_ID must be set in connection config or environment")
	}

	token := os.Getenv("SENTINELONE_API_TOKEN")
	if cfg.APIToken != nil {
		token = *cfg.APIToken
	}
	if token == "" {
		return nil, errors.New("SENTINELONE_API_TOKEN must be set in connection config or environment")
	}

	client := &SentinelOneClient{
		BaseURL:  tenant,
		APIToken: token,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &authTransport{underlying: http.DefaultTransport, token: token},
		},
	}

	d.ConnectionManager.Cache.Set(cacheKey, client)
	return client, nil
}
