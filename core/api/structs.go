package api

const (
	ERR_DOMAIN_NOT_FOUND         = "ERR_DOMAIN_NOT_FOUND"
	ERR_ACTION_NOT_FOUND         = "ERR_ACTION_NOT_FOUND"
	ERR_BODY_READ_FAILED         = "ERR_BODY_READ_FAILED"
	ERR_JSON_READ_FAILED         = "ERR_JSON_READ_FAILED"
	ERR_INVALID_PARAM            = "ERR_INVALID_PARAM"
	ERR_PARAMS_REQUIRED          = "ERR_PARAMS_REQUIRED"
	ERR_CONFIG_WRITE_FAILED      = "ERR_CONFIG_WRITE_FAILED"
	ERR_RELOAD_FAILED            = "ERR_RELOAD_FAILED"
	ERR_FETCH_FAILED             = "ERR_FETCH_FAILED"
	ERR_APPROVAL_REQUIRED        = "ERR_APPROVAL_REQUIRED"
	ERR_APPROVAL_NOT_FOUND       = "ERR_APPROVAL_NOT_FOUND"
	ERR_FORBIDDEN                = "ERR_FORBIDDEN"
	ERR_JSON_LOGS_NOT_CONFIGURED = "ERR_JSON_LOGS_NOT_CONFIGURED"
)

type API_REQUEST struct {
	Domain string            `json:"domain"`
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

type API_RESPONSE struct {
	Success  bool                   `json:"success"`
	Response map[string]interface{} `json:"results"`
}
