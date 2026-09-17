// HTTP status codes shared by the three roles' error responses.
package common

import "net/http"

const (
	ServerError              = http.StatusInternalServerError
	StatusBadGateway         = http.StatusBadGateway
	StatusServiceUnavailable = http.StatusServiceUnavailable
	InternalError            = 504

	BadRequest   = http.StatusBadRequest
	Unauthorized = http.StatusUnauthorized
	Forbidden    = http.StatusForbidden
	NotFound     = http.StatusNotFound

	StatusOK      = http.StatusOK
	StatusCreated = http.StatusCreated
)
