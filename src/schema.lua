local url = require "socket.url"

local function validate_url(value)
  local parsed_url = url.parse(value)
  if parsed_url.scheme and parsed_url.host then
    parsed_url.scheme = parsed_url.scheme:lower()
    if not (parsed_url.scheme == "http" or parsed_url.scheme == "https") then
      return false, "Supported protocols are HTTP and HTTPS"
    end
  end

  return true
end

return {
  fields = {
    domain_name = {type = "string", required = true},
    application_id = {type = "string", required = true},
    application_key = {type = "string", required = true},
    signin_policy  = {type = "string", required = true},
    validation_host = {type = "string", required = true},
    user_info_periodic_check = {type = "number", required = true, default = 60},
    
  }
}
