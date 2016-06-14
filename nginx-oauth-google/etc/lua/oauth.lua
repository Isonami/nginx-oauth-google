local level = ngx.DEBUG
local oauth_client_id = ngx.var.oauth_client_id
local oauth_client_secret = ngx.var.oauth_client_secret
local oauth_callback = ngx.escape_uri(ngx.var.oauth_callback)
local oauth_server  = ngx.var.oauth_server
local method = ngx.var.request_method
local getmetatable = getmetatable
local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef
local ffi_new      = ffi.new
local ffi_str      = ffi.string
local ffi_typeof   = ffi.typeof
local C            = ffi.C
package.path = package.path..";/usr/local/etc/nginx/lua/?.lua"
ngx.log(level, package.path)
local emails       = require "emails" 
local hour         = 3600

ffi_cdef[[
typedef unsigned char u_char;
int RAND_bytes(u_char *buf, int num);
]]

local t = ffi_typeof "uint8_t[?]"

local function random(len)
    local s = ffi_new(t, len)
    C.RAND_bytes(s, len)
    return ffi_str(s, len)
end
ngx.log(level, ngx.var.uri) 


local session = require "resty.session".open()
local temp = ngx.shared.temp
ngx.log(level, "get: "..ngx.encode_base64(ngx.var.cookie_session))
local auth
local authstr = temp:get(ngx.encode_base64(ngx.var.cookie_session))
ngx.log(level, "auth: "..type(authstr))
if authstr then
    auth = {}
    for i in ngx.re.gmatch(authstr, "[^|]+") do
        if auth.user then
            auth.token = i[0]
        else
            auth.user = i[0]
        end
    end
end
local save = false
local allow = true

function get_email()
    ngx.log(level, "get_email...")
    local res = ngx.location.capture(
        '/_oauth_server_email',
        { args = { access_token = session.data.access_token } }
    )
    if res.status ~= 200 then
        session:destroy()
        ngx.log(level, "status: "..res.status..", error: "..ngx.re.gsub(res.body, "\"", "\\\""))
        ngx.status = res.status
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.say("{\"status\": "..res.status..", \"error\": \""..ngx.re.gsub(res.body, "\"", "\\\"").."\"}")
        allow = false
        return
    end
    local content = res.body
    local result_dict = require "cjson".decode(content)
    for key, value in pairs(result_dict.emails) do
        ngx.log(level, key)
        ngx.log(level, value.value)
    end
    ngx.log(level, "email: "..result_dict.emails[1].value)
    return result_dict.emails[1].value
end

function get_access_token()
    ngx.log(level, "get_access_token...")
    session:start()
    local res = ngx.location.capture(
        '/_oauth_server',
        { method = ngx.HTTP_POST, body = "client_id="..oauth_client_id.."&client_secret="..oauth_client_secret.."&code="..session.data.auth_token.."&grant_type=authorization_code&redirect_uri="..oauth_callback }
    )
    if res.status ~= 200 then
        session:destroy()
        ngx.status = res.status
        ngx.log(level, "status: "..res.status..", error: "..ngx.re.gsub(res.body, "\"", "\\\""))
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.say("{\"status\": "..res.status..", \"error\": \""..ngx.re.gsub(res.body, "\"", "\\\"").."\"}")
        allow = false
        return
    end
    local content = res.body
    local result_dict = require "cjson".decode(content)
    session.data.access_token = result_dict.access_token
    session.data.token_type = result_dict.token_type
    user = get_email()
    if not user then
        return
    end
    session.data.user = user
    session.data.expires_at = result_dict.expires_in + ngx.now() + ngx.var.session_cookie_lifetime - hour
    --session.data.expires_at = 20 + ngx.now()
    if result_dict.refresh_token then
        session.data.refresh_token = result_dict.refresh_token
    end
    ngx.log(level, "access_tiken: "..session.data.access_token..", token_type: "..session.data.token_type..", user: "..session.data.user..", expires_at: "..session.data.expires_at)
    if result_dict.refresh_token then
        ngx.log(level, "refresh_token: "..session.data.refresh_token)
    end
    session.data.auth_token = nil
    save = true
    return
end

function get_auth_token()
    if method == "POST" then
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("{\"status\": 401, \"message\": \"session uknown or expired\"}")
        allow = false
        return
    end
    return "/login?next="..ngx.escape_uri(ngx.var.uri)
--[[    if session.data.sended and session.data.sended > ngx.now() then
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.status = ngx.HTTP_OK
        ngx.say("{\"status\": 401, \"message\": \"already authorized\"}")
        allow = false
        return ngx.exit(ngx.OK)
    end
    ngx.log(level, "get_auth_token...")
    state = ngx.re.gsub(ngx.encode_base64(random(24)), "[+ ]", "a")
    session:start()
    session.data.next = ngx.var.uri
    session.data.state = state
    session.data.sended = ngx.now() + 10
    session.data.access_token = nil
    session.data.token_type = nil
    session.data.user = nil
    session.data.expires_at = nil
    session.data.refresh_token = nil
    session:save()
    return "https://"..oauth_server.."/auth?client_id="..oauth_client_id.."&redirect_uri="..oauth_callback.."&response_type=code&scope="..ngx.escape_uri("email profile").."&state="..ngx.escape_uri(state)]]
end

function update_access_token()
    ngx.log(level, "update_access_token...")
    if not session.data.refresh_token then
        return get_auth_token()
    end
    ngx.log(level, "refresh_token: "..session.data.refresh_token)
    session:start()
    ngx.log(level, "start update")
    local res = ngx.location.capture(
        '/_oauth_server',
        { method = ngx.HTTP_POST, body = "client_id="..oauth_client_id.."&client_secret="..oauth_client_secret.."&refresh_token="..session.data.refresh_token.."&grant_type=refresh_token&redirect_uri="..oauth_callback }
    )
    ngx.log(level, "refresh status: "..res.status)
    if res.status ~= 200 then
        session:destroy()
        ngx.status = res.status
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.say("{\"status\": "..res.status..", \"error\": \""..ngx.re.gsub(res.body, "\"", "\\\"").."\"}")
        allow = false
        return
    end
    local content = res.body
    local result_dict = require "cjson".decode(content)
    session.data.access_token = result_dict.access_token
    session.data.token_type = result_dict.token_type
    session.data.expires_at = result_dict.expires_in + ngx.now()
    --session.data.expires_at = 20 + ngx.now()
    if result_dict.refresh_token then
        session.data.refresh_token = result_dict.refresh_token
    end
    ngx.log(level, "access_tiken: "..session.data.access_token..", token_type: "..session.data.token_type..", user: "..session.data.user..", expires_at: "..session.data.expires_at..", refresh_token: "..session.data.refresh_token)
    save = true
    ngx.log(level, "set: "..ngx.encode_base64(ngx.var.cookie_session))
    temp:set(ngx.encode_base64(ngx.var.cookie_session), session.data.user.."|"..session.data.access_token, 30)
    return
end

local args = ngx.req.get_uri_args()
if args.error and args.error == "access_denied" then
    if save then
        session:save()
    end
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    if args.error == "access_denied" then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("{\"status\": 401, \"message\": \""..args.error.."\"}")
    else
        ngx.status = ngx.HTTP_BAD_GATEWAY
        ngx.say("{\"status\": 502, \"error\": \""..args.error.."\"}")
    end
    return ngx.exit(ngx.OK)
end

if not auth or not auth.token then
    if not session.data.access_token then
        local redirect
        if not session.data.auth_token then
            redirect = get_auth_token()
        else
            redirect = get_access_token()
        end
        if redirect then
            return ngx.redirect(redirect)
        end
    end

    if session.data.expires_at and session.data.expires_at < ngx.now() then
        local redirect
        redirect =  update_access_token()
        if redirect then
            return ngx.redirect(redirect)
        end
    end

    if save then
        ngx.log(level, "save: true")
        session:save()
    end
    if not emails[session.data.user] then
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.status = ngx.HTTP_UNAUTHORIZED                                                                       
        ngx.say("{\"status\": 401, \"message\": \"user not allowed\"}")
        return ngx.exit(ngx.OK)
    end
    ngx.var.oauth_user = session.data.user
else
    ngx.var.oauth_user = auth.user
end

if allow then
    ngx.exec("@content")
end

