package okta

import "time"

// HTTP client configuration.
const HTTPTimeout = 30 * time.Second

// Rate limiting.
const (
	maxRateLimitRetries = 3
	maxRateLimitWait    = 60 * time.Second
	defaultBackoff      = time.Second
)

// OAuth configuration.
const jwtExpiry = 5 * time.Minute

// Pagination.
const paginationLimit = 200
