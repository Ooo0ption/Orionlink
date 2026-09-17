package common

import "net/http"

const (
	// 5xx 服务器端错误
	ServerError              = http.StatusInternalServerError // 500
	StatusBadGateway         = http.StatusBadGateway          // 502
	StatusServiceUnavailable = http.StatusServiceUnavailable  // 503
	InternalError            = 504                            // 504

	// 4xx 客户端错误
	BadRequest   = http.StatusBadRequest   // 400
	Unauthorized = http.StatusUnauthorized // 401
	Forbidden    = http.StatusForbidden    // 403
	NotFound     = http.StatusNotFound     // 404

	// 2xx 成功
	StatusOK      = http.StatusOK      // 200
	StatusCreated = http.StatusCreated // 201
)
