local start_html = [[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign in</title>
    <style>
        .outer {
            display: table;
            position: absolute;
            height: 90%;
            width: 99%;
        }

        .middle {
            display: table-cell;
            vertical-align: middle;
        }

        .inner {
            margin-left: auto;
            margin-right: auto;
            width: 388px;
        }
        .header {
            margin-bottom: 0;
            margin-left: 5px;
            font-size: xx-large;
        }
    </style>
</head>
<body>
<div class="outer">
    <div class="middle">
        <div class="inner">

            <span class="header">Sign in</span>
            <form method="post">
                <input type="hidden" name="next" value="]]
local end_html = [[">
                <input type="image" id="google" src="/login/btn_google_signin.png" />
            </form>
        </div>
    </div>
</div>
</body>
</html>]]
local method = ngx.var.request_method
local level = ngx.DEBUG
local nxt
local oauth_client_id = ngx.var.oauth_client_id
local oauth_client_secret = ngx.var.oauth_client_secret
local oauth_callback = ngx.escape_uri(ngx.var.oauth_callback)
local oauth_server  = ngx.var.oauth_server
local session = require "resty.session".open()
local ffi          = require "ffi"
local ffi_cdef     = ffi.cdef
local ffi_new      = ffi.new
local ffi_str      = ffi.string
local ffi_typeof   = ffi.typeof
local C            = ffi.C

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


function get_auth_token()
    if session.data.sended and session.data.sended > ngx.now() then
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.status = ngx.HTTP_OK
        ngx.say("{\"status\": 401, \"message\": \"already authorized\"}")
        return ngx.exit(ngx.OK)
    end
    ngx.log(level, "get_auth_token...")
    state = ngx.re.gsub(ngx.encode_base64(random(24)), "[+ ]", "a")
    session:start()
    session.data.next = nxt
    session.data.state = state
    session.data.sended = ngx.now() + 10
    session.data.access_token = nil
    session.data.token_type = nil
    session.data.user = nil
    session.data.expires_at = nil
    session.data.refresh_token = nil
    session:save()
    return "https://"..oauth_server.."/auth?client_id="..oauth_client_id.."&redirect_uri="..oauth_callback.."&response_type=code&scope="..ngx.escape_uri("email profile").."&state="..ngx.escape_uri(state)
end

if method == "POST" then
    ngx.req.read_body()
    local args = ngx.req.get_post_args()
    nxt = args.next
    if not nxt then
        nxt = '/'
    end
    local session = require "resty.session".open()
    if session.data.access_token and session.data.expires_at and session.data.expires_at > ngx.now() then
        return ngx.redirect(nxt)
    end
    return ngx.redirect(get_auth_token())
else
    local args = ngx.req.get_uri_args()
    nxt = args.next
    if not nxt then
        nxt = '/'
    end
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.say(start_html..nxt..end_html)
    return ngx.exit(ngx.HTTP_OK)
end
