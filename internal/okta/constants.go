package okta

import "time"

// OAuth configuration.
const jwtExpiry = 5 * time.Minute

// Pagination.
const paginationLimit = 200

// maxResponseBytes bounds how much of one response the client reads.
const maxResponseBytes = 16 << 20
