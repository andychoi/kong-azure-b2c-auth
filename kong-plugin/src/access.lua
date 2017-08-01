
-- Copyright 2016 Niko Usai

--    Licensed under the Apache License, Version 2.0 (the "License");
--    you may not use this file except in compliance with the License.
--    You may obtain a copy of the License at

--        http://www.apache.org/licenses/LICENSE-2.0

--    Unless required by applicable law or agreed to in writing, software
--    distributed under the License is distributed on an "AS IS" BASIS,
--    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--    See the License for the specific language governing permissions and
-- limitations under the License.

local _M = {}
local cjson = require "cjson.safe"
local pl_stringx = require "pl.stringx"
local http = require "resty.http"
local crypto = require "crypto"

local OAUTH_CALLBACK = "^%s/oauth2/callback(/?(\\?[^\\s]*)*)$"

function _M.run(conf)
    status, err = pcall(function() return handle_azure(conf) end)

    if not status then
        ngx.status = 500
        ngx.say("error in azure auth:\n\n" .. err)
        ngx.exit(ngx.HTTP_OK)
    end
end

function handle_azure(conf)

     -- Check if the API has a request_path and if it's being invoked with the path resolver
    local path_prefix = ""

    if ngx.ctx.api.uris ~= nil then
        for index, value in ipairs(ngx.ctx.api.uris) do
            if pl_stringx.startswith(ngx.var.request_uri, value) then
                path_prefix = value
                break
            end
        end

        if pl_stringx.endswith(path_prefix, "/") then
            path_prefix = path_prefix:sub(1, path_prefix:len() - 1)
        end

    end

    local azure_base_url = "https://login.microsoftonline.com/" .. conf.domain_name .. "/oauth2/v2.0"
    local callback_url = ngx.var.scheme .. "://" .. ngx.var.host.. ":8000" .. path_prefix .. "/oauth2/callback"

    -- check if we're calling the callback endpoint
    if ngx.re.match(ngx.var.request_uri, string.format(OAUTH_CALLBACK, path_prefix)) then
        handle_callback(conf,azure_base_url, callback_url)
    else
        local encrypted_token = ngx.var.cookie_EOAuthToken
        -- check if we are authenticated already
        if encrypted_token then
        
            add_cookie("EOAuthToken=" .. encrypted_token .. "; path=/;Max-Age=3000;HttpOnly")

            local cookieToken = cjson.decode(decode_token(encrypted_token, conf))
            if not cookieToken then
                -- broken access token
                return redirect_to_auth( conf,azure_base_url, callback_url )
            end

            

            add_cookie("AzureAuthToken=".. ngx.encode_base64(cjson.encode(cookieToken["decoded"])) .. "; path=/;Max-Age=3000;")


        else
            return redirect_to_auth( conf,azure_base_url, callback_url )
        end
    end

end

function redirect_to_auth( conf,azurebase, callback_url )
    -- Track the endpoint they wanted access to so we can transparently redirect them back
    ngx.header["Set-Cookie"] = "EOAuthRedirectBack=" .. ngx.var.request_uri .. "; path=/;Max-Age=120"
    -- Redirect to the /oauth endpoint
    local oauth_authorize = azurebase .. "/authorize?response_type=code&response_mode=query&p=".. conf.signin_policy .."&client_id=" .. conf.application_id .. "&redirect_uri=" .. callback_url .. "&scope=openid%20offline_access%20" .. conf.application_id
    return ngx.redirect(oauth_authorize)
end

function encode_token(token, conf)
    return ngx.encode_base64(crypto.encrypt("aes-128-cbc", token, crypto.digest('md5',conf.application_key)))
    --return ngx.encode_base64(token)
end

function decode_token(token, conf)
    status, token = pcall(function () return crypto.decrypt("aes-128-cbc", ngx.decode_base64(token), crypto.digest('md5',conf.application_key)) end)
    --status, token = pcall(function () return ngx.decode_base64(token) end)
    if status then
        return token
    else
        return nil
    end
end

-- Callback Handling
function  handle_callback( conf,azurebase, callback_url )
    local args = ngx.req.get_uri_args()

    if args.code then
        local httpc = http:new()
        local res, err = httpc:request_uri(azurebase .. "/token?p=" .. conf.signin_policy, {
            method = "POST",
            ssl_verify = false,
            body = "grant_type=authorization_code&client_id=" .. conf.application_id .. "&client_secret=".. conf.application_key .."&code=" .. args.code .. "&redirect_uri=" .. callback_url,
            headers = {
              ["Content-Type"] = "application/x-www-form-urlencoded",
            }
        })

        if not res then
            ngx.status = res.status
            ngx.say("failed to request: ", err)
            ngx.exit(ngx.HTTP_OK)
        end

        status, json = pcall(function() return cjson.decode(res.body) end)

        if not status then
            ngx.status = 500
            ngx.say("unable to parse response:" .. res.body)
            ngx.exit(ngx.HTTP_OK)
        end

        local access_token = json.access_token
        if not access_token then
            ngx.status = 500
            ngx.say(json.error_description)
            ngx.exit(ngx.HTTP_OK)
        end

        --check against validation service
        local vRes, vErr = httpc:request_uri("http://" .. conf.validation_host .. "/verify?token=" .. access_token, { method = "GET"})
        if not vRes then
            ngx.status = 500
            ngx.say("unable to verify token using " .. conf.validation_host .. " --> " .. vErr)
            ngx.exit(ngx.HTTP_OK)
        end
        local verifyJson = cjson.decode(vRes.body)
        if not verifyJson.token_valid then
            ngx.status = 403
            ngx.say("invalid token")
            ngx.exit(ngx.HTTP_OK)
        end

        local cookieToken = {}
        cookieToken["decoded"] = verifyJson.decoded_token;
        cookieToken["token"] = access_token;
        
        --token is valid and we can use stuff from it
        add_cookie("EOAuthToken="..encode_token( cjson.encode(cookieToken), conf ) .. "; path=/;Max-Age=3000;HttpOnly")
        -- Support redirection back to your request if necessary
        local redirect_back = ngx.var.cookie_EOAuthRedirectBack
        if redirect_back then
            return ngx.redirect(redirect_back)
        else
            return ngx.redirect(ngx.ctx.api.request_path)
        end
    else
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.say("User has denied access to the resources.")
        ngx.exit(ngx.HTTP_OK)
    end
end

function get_cookies()
  local cookies = ngx.header["Set-Cookie"] or {}
 
  if type(cookies) == "string" then
    cookies = {cookies}
  end
 
  return cookies
end
 
 
function add_cookie(cookie)
  local cookies = get_cookies()
  table.insert(cookies, cookie)
  ngx.header['Set-Cookie'] = cookies
end
return _M
