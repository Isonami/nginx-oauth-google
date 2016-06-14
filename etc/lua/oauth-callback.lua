local session = require "resty.session".start()
local level = ngx.DEBUG

local args = ngx.req.get_uri_args()
if args.error then
    session:save()
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    if args.error == "access_denied" then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("{\"status\": 401, \"message\": \""..args.error.."\"}")
    else
        ngx.status = ngx.HTTP_BAD_GATEWAY
        ngx.say("{\"status\": 502, \"error\": \""..args.error.."\"}")
    end
    ngx.exit(ngx.HTTP_OK)
end

if (session.data.access_token) then
    if (session.data.next or args.next) then
        if args.next then
            return ngx.redirect(ngx.unescape_uri(args.next))
        else
            return ngx.redirect(session.data.next)
        end
    else
        return ngx.redirect("/")
    end
end

if (session.data.next or args.next) and args.code then
    ngx.log(level, ngx.unescape_uri(args.state).." "..session.data.state)
    if args.state and ngx.unescape_uri(args.state) == session.data.state then
        session.data.auth_token = args.code
        ngx.log(level, args.state)
        session:save()
        if args.next then
            return ngx.redirect(ngx.unescape_uri(args.next))
        else
            return ngx.redirect(session.data.next)
        end
    else
        session:destroy()
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say("{\"status\": 401, \"message\": \"invalid state\"}")
        ngx.exit(ngx.HTTP_OK)
    end
else
    session:destroy()
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.say("{\"status\": 401, \"message\": \"no next uri\"}")
    ngx.exit(ngx.HTTP_OK)
end

