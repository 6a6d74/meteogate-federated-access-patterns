--
-- friendly-errors — explain a gateway refusal to whoever is asking.
--
-- A gateway that refuses a request has to answer two different audiences with the same
-- status code. A script wants `{"error": "..."}` on stderr and a non-zero exit. A person
-- who has just pasted a URL into Chrome wants to know what went wrong, whether it is
-- their fault, and what to do next.
--
-- This plugin does content negotiation on the error path: JSON stays JSON unless the
-- client said it prefers HTML, in which case the body is replaced with a page that names
-- the problem and links to the fix.
--
-- It runs in header_filter/body_filter, which OpenResty executes for plugin-generated
-- responses as well as upstream ones — so a 401 from openid-connect and a 429 from
-- limit-count are both reachable from here.
--
-- Install: mounted at /opt/apisix/plugins/friendly-errors.lua, with
--   apisix.extra_lua_path: "/opt/?.lua"
-- and "friendly-errors" listed in the `plugins` array of config.yaml.
--

local core    = require("apisix.core")
local ngx     = ngx
local str_fmt = string.format
local concat  = table.concat

local schema = {
    type = "object",
    properties = {
        mode = {
            type = "string",
            enum = { "federated", "apikey", "open" },
            default = "federated",
            description = "Which credential this route expects, so the page can explain the right one.",
        },
        service_name = { type = "string", default = "this service" },
        portal_url   = { type = "string", default = "" },
        docs_url     = { type = "string", default = "" },
        token_url    = { type = "string", default = "" },
        issuer       = { type = "string", default = "" },
        cli_client   = { type = "string", default = "federation-cli" },
        account_name = { type = "string", default = "meteogate" },
        contact      = { type = "string", default = "" },
    },
}

local _M = {
    version  = 0.1,
    -- Low priority: header_filter and body_filter run in descending priority order, so a
    -- small number means this sees the status after every other plugin has had its say.
    priority = 50,
    name     = "friendly-errors",
    schema   = schema,
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end


-- ---------------------------------------------------------------------------
-- Content negotiation
-- ---------------------------------------------------------------------------

-- A browser navigating to a URL sends `Accept: text/html,...`. curl sends `*/*`, and
-- fetch() from JavaScript is normally told to send `application/json`. Matching on
-- text/html therefore separates "a person is looking at this" from everything else
-- without guessing at User-Agent strings, which lie.
local function wants_html(ctx)
    local accept = ctx.var.http_accept
    if accept and core.string.find(accept, "text/html") then
        return true
    end
    -- Fetch Metadata, where the browser supports it: a top-level navigation is a person.
    return ctx.var.http_sec_fetch_dest == "document"
end


-- ---------------------------------------------------------------------------
-- Page content
-- ---------------------------------------------------------------------------

local STYLE = [[
:root{--bg:#f6f5f2;--panel:#fff;--ink:#1c1b19;--muted:#6b6862;--line:#dedbd4;
--accent:#2f6f4e;--accent-ink:#fff;--warn:#b3541e;--code:#f0efeb}
@media(prefers-color-scheme:dark){:root{--bg:#17181a;--panel:#212327;--ink:#ececea;
--muted:#9a978f;--line:#33363b;--accent:#5fae83;--accent-ink:#10120f;--warn:#e08b4c;--code:#1a1c1f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:42rem;margin:0 auto;padding:3rem 1.25rem 4rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:1.5rem 1.6rem}
.status{display:inline-block;font-size:.72rem;font-weight:700;letter-spacing:.09em;
text-transform:uppercase;color:var(--warn);border:1px solid var(--warn);
border-radius:99px;padding:.15rem .6rem;margin-bottom:.9rem}
h1{margin:0 0 .5rem;font-size:1.35rem;letter-spacing:-.01em}
p{margin:.7rem 0}
.lead{color:var(--muted)}
ol,ul{margin:.7rem 0;padding-left:1.3rem}
li{margin:.35rem 0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.84rem}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;
padding:.8rem .9rem;overflow-x:auto;margin:.8rem 0}
a{color:var(--accent)}
.cta{display:inline-block;margin-top:1rem;padding:.55rem 1.2rem;border-radius:8px;
background:var(--accent);color:var(--accent-ink);text-decoration:none;font-weight:600}
.foot{margin-top:1.4rem;padding-top:1rem;border-top:1px solid var(--line);
color:var(--muted);font-size:.82rem}
.foot code{color:var(--muted)}
.snip{position:relative}
.snip>button.copy{position:absolute;top:.4rem;right:.4rem;font:inherit;font-size:.68rem;
font-weight:600;letter-spacing:.06em;text-transform:uppercase;padding:.2rem .5rem;
border-radius:5px;cursor:pointer;border:1px solid var(--line);background:var(--panel);
color:var(--muted);opacity:0;transition:opacity .12s ease}
.snip:hover>button.copy,.snip:focus-within>button.copy{opacity:1}
.snip>button.copy:focus-visible{opacity:1;outline:2px solid var(--accent);outline-offset:1px}
.snip>button.copy.done{color:var(--accent);border-color:var(--accent)}
@media(hover:none){.snip>button.copy{opacity:1}}
@media(prefers-reduced-motion:reduce){.snip>button.copy{transition:none}}
]]


local COPY_SCRIPT = [[
(function(){
  var s=document.createElement("style");
  document.querySelectorAll("pre").forEach(function(pre){
    var w=document.createElement("div");w.className="snip";
    pre.parentNode.insertBefore(w,pre);w.appendChild(pre);
    var b=document.createElement("button");
    b.type="button";b.className="copy";b.textContent="Copy";
    b.setAttribute("aria-label","Copy this snippet to the clipboard");
    var t;
    b.addEventListener("click",function(){
      clearTimeout(t);
      var text=pre.textContent,done=function(ok){
        b.textContent=ok?"Copied":"Press ⌘C";
        b.className=ok?"copy done":"copy";
        t=setTimeout(function(){b.textContent="Copy";b.className="copy";},1800);
      };
      var legacy=function(){
        var a=document.createElement("textarea");a.value=text;a.setAttribute("readonly","");
        a.style.position="fixed";a.style.top="-1000px";document.body.appendChild(a);a.select();
        a.setSelectionRange(0,text.length);
        var ok=false;try{ok=document.execCommand("copy");}catch(e){ok=false;}
        document.body.removeChild(a);return ok;
      };
      // writeText can reject even where navigator.clipboard exists and the context is
      // secure; fall through rather than treating that as final.
      if(navigator.clipboard&&window.isSecureContext){
        navigator.clipboard.writeText(text).then(function(){done(true);},function(){done(legacy());});
      }else{ done(legacy()); }
    });
    w.appendChild(b);
  });
})();
]]

local function esc(value)
    if not value then return "" end
    return (tostring(value):gsub("[&<>\"]", {
        ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;",
    }))
end

local function page(status, label, title, body_html, conf, ctx)
    local footer = { str_fmt("Gateway response <code>%d</code> for <code>%s</code>",
                             status, esc(ctx.var.request_uri)) }
    if conf.contact ~= "" then
        footer[#footer + 1] = "Operator contact: " .. esc(conf.contact)
    end

    return concat({
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>", esc(title), " — ", esc(conf.service_name), "</title>",
        "<style>", STYLE, "</style></head><body><div class=\"wrap\"><div class=\"card\">",
        "<span class=\"status\">", esc(label), "</span>",
        "<h1>", esc(title), "</h1>",
        body_html,
        "<p class=\"foot\">", concat(footer, "<br>"), "</p>",
        "</div></div><script>", COPY_SCRIPT, "</script></body></html>",
    })
end


-- 401 — no usable credential was presented.
local function unauthorized(conf, ctx)
    local body
    if conf.mode == "apikey" then
        body = concat({
            "<p class=\"lead\">This route is protected by an API key that ",
            esc(conf.service_name),
            " issues and manages itself. It is nothing to do with the federation.</p>",
            "<p>Send the key in the <code>apikey</code> header:</p>",
            "<pre>curl -H 'apikey: YOUR-KEY' \\\n  '", esc(ctx.var.scheme), "://",
            esc(ctx.var.host), esc(ctx.var.request_uri), "'</pre>",
            "<p>If you do not have a key, ask the service operator for one. ",
            "Keys are held locally and are not federated.</p>",
        })
    else
        local steps = {
            "<p class=\"lead\">This route needs a federation credential. ",
            "One credential works across every service in the federation, and it is ",
            "checked here at the gateway — the request never left this machine.</p>",
            "<h2 style=\"font-size:1rem;margin-top:1.4rem\">In a browser</h2>",
            "<p>Use the web client, which signs you in and attaches the token for you.</p>",
        }
        if conf.portal_url ~= "" then
            steps[#steps + 1] = str_fmt(
                "<p>No account yet? Register at the <a href=\"%s\">Federation Portal</a>. "
                .. "Registration is through GitHub — there is no password to choose.</p>",
                esc(conf.portal_url))
        end
        steps[#steps + 1] = "<h2 style=\"font-size:1rem;margin-top:1.4rem\">At a terminal</h2>"

        -- Everyone reading this page has NO working credential — that is why they are
        -- here. So the terminal instructions must start from nothing installed and
        -- nothing configured. An earlier version of this page printed
        -- `oidc-token meteogate` with a "# after one-time setup" comment, which fails
        -- with "did not receive any response" for exactly the population it was written
        -- for. Show the setup, then the use.
        -- Name the package, the daemon and the commands separately. They are all
        -- called some variation of "oidc-agent", which reads as obvious once you know
        -- it and as a typo before then: the page said "use oidc-agent" and then handed
        -- over a command called oidc-gen with no explanation of the relationship.
        steps[#steps + 1] = str_fmt(
            "<p>Install <a href=\"https://github.com/indigo-dc/oidc-agent\">oidc-agent</a> "
            .. "— a small suite of command-line tools, plus a background daemon that holds "
            .. "your credential on the <code>ssh-agent</code> model. The package takes its "
            .. "name from the daemon; the commands you actually type are "
            .. "<code>oidc-gen</code> to register, and <code>oidc-token</code> to fetch a "
            .. "token. <a href=\"%s://%s/help/\">Installation, per platform</a>.</p>",
            esc(ctx.var.scheme), esc(ctx.var.host))
        steps[#steps + 1] =
            "<p>Once installed, register this machine — it prints a code to approve in a "
            .. "browser:</p>"
        steps[#steps + 1] = concat({
            "<pre>oidc-gen ", esc(conf.account_name), " --flow=device --manual \\\n",
            "  --iss=", esc(conf.issuer ~= "" and conf.issuer or "&lt;issuer&gt;"), " \\\n",
            "  --client-id=", esc(conf.cli_client), " \\\n",
            "  --scope='openid profile email offline_access'</pre>",
        })
        steps[#steps + 1] = "<p>Then, for this and every other request:</p>"
        steps[#steps + 1] = concat({
            "<pre>curl --oauth2-bearer \"$(oidc-token ", esc(conf.account_name), ")\" \\\n  '",
            esc(ctx.var.scheme), "://", esc(ctx.var.host),
            esc(ctx.var.request_uri), "'</pre>",
        })
        steps[#steps + 1] = str_fmt(
            "<p>If <code>oidc-token</code> answers "
            .. "<code>did not receive any response</code>, the agent is not reachable from "
            .. "that shell — see <a href=\"%s://%s/help/\">the access guide</a>.</p>",
            esc(ctx.var.scheme), esc(ctx.var.host))
        if conf.token_url ~= "" then
            steps[#steps + 1] = str_fmt(
                "<p>Or exchange a machine credential for a token at "
                .. "<code>%s</code> and send it as <code>Authorization: Bearer …</code>.</p>",
                esc(conf.token_url))
        end
        if conf.portal_url ~= "" then
            steps[#steps + 1] = str_fmt("<a class=\"cta\" href=\"%s\">Go to the Federation Portal</a>",
                                        esc(conf.portal_url))
        end
        body = concat(steps)
    end
    return page(401, "401 Unauthorized", "You need a credential to read this", body, conf, ctx)
end


-- 403 — the credential was genuine, but not good enough for this route.
local function forbidden(conf, ctx)
    local body = concat({
        "<p class=\"lead\">Your credential is valid, but it does not carry permission ",
        "for this resource.</p>",
        "<p>The usual causes:</p>",
        "<ul>",
        "<li>the token was issued for a different audience, so it is not accepted here;</li>",
        "<li>the token has expired — they are short-lived by design, so fetch a new one;</li>",
        "<li>your registration lacks an entitlement this collection requires.</li>",
        "</ul>",
        conf.portal_url ~= ""
            and str_fmt("<p>Check what your registration carries at the "
                        .. "<a href=\"%s\">federation portal</a>.</p>", esc(conf.portal_url))
            or "",
    })
    return page(403, "403 Forbidden", "That credential will not open this door", body, conf, ctx)
end


-- 429 — the credential was fine; there have simply been too many requests.
local function too_many(conf, ctx)
    -- limit-count advertises the window in response headers; reuse them rather than
    -- restating a policy that lives in the route config.
    local limit  = ngx.header["X-RateLimit-Limit"]
    local reset  = ngx.header["X-RateLimit-Reset"]

    local quota_line = limit
        and str_fmt("<p>This route allows <strong>%s requests</strong> per window.</p>", esc(limit))
        or  "<p>This route has a request quota, and you have reached it.</p>"

    local reset_line = reset
        and str_fmt("<p>The window resets in <strong>%s seconds</strong>. "
                    .. "Wait that long and try again — nothing is broken and nothing is "
                    .. "blocked permanently.</p>", esc(reset))
        or  "<p>Wait for the current window to elapse and try again.</p>"

    local body = concat({
        "<p class=\"lead\">Your credential was accepted. You have simply made more ",
        "requests than the quota allows.</p>",
        quota_line, reset_line,
        "<p>Quotas are counted per credential, at each service, so a busy job of yours ",
        "at one service does not spend another user's allowance.</p>",
        "<p>If you are pulling a lot of data, ask ", esc(conf.service_name),
        " about a higher quota rather than working around this.</p>",
    })
    return page(429, "429 Too Many Requests", "You have used up your quota", body, conf, ctx)
end


-- 502/503/504 — the gateway is fine; the thing behind it is not.
local function upstream_down(conf, ctx, status)
    local body = concat({
        "<p class=\"lead\">The gateway is running, but ", esc(conf.service_name),
        " behind it did not answer.</p>",
        "<p>This is not a problem with your credential and there is nothing to fix at ",
        "your end. Try again shortly.</p>",
        conf.docs_url ~= ""
            and str_fmt("<p>Service documentation: <a href=\"%s\">%s</a></p>",
                        esc(conf.docs_url), esc(conf.docs_url))
            or "",
    })
    return page(status, status .. " Upstream unavailable",
                "The service behind this gateway is not responding", body, conf, ctx)
end


local RENDERERS = {
    [401] = unauthorized,
    [403] = forbidden,
    [429] = too_many,
}


-- ---------------------------------------------------------------------------
-- The other half of the job.
--
-- Content negotiation cuts both ways, and the direction that is easy to forget is
-- the one that matters more. When openid-connect refuses a request it sets
-- WWW-Authenticate and exits with no body at all, so nginx fills in its stock error
-- page — which is HTML. A script asking for JSON gets a chunk of markup and a title
-- tag, which is exactly the wrong answer for the client most likely to be refused.
--
-- So: if the client did not ask for HTML and the body is HTML anyway, replace it with
-- something a program can read. A body some other plugin already produced as JSON is
-- left alone.
-- ---------------------------------------------------------------------------

local CODES = {
    [400] = "bad_request",
    [401] = "unauthorized",
    [403] = "forbidden",
    [429] = "quota_exceeded",
    [502] = "upstream_unavailable",
    [503] = "upstream_unavailable",
    [504] = "upstream_timeout",
}

-- Format strings rather than plain ones: the help URL is derived from the request, so
-- a JSON client is pointed at the same page as a browser rather than at a command that
-- assumes it is already set up. `%s` is the help URL.
local DETAILS = {
    federated = {
        [401] = "No valid federation credential was presented. Send an "
             .. "'Authorization: Bearer <token>' header. To obtain a token, see %s",
        [403] = "The token is valid but not accepted here. Check its audience, and that "
             .. "it has not expired. See %s",
    },
    apikey = {
        [401] = "No valid API key was presented. Send it in the 'apikey' header. "
             .. "Keys are issued by the service operator, not by the federation. See %s",
    },
}

local function machine_readable(conf, ctx, status)
    local help_url = str_fmt("%s://%s/help/", ctx.var.scheme, ctx.var.host)
    local mode_details = DETAILS[conf.mode] or {}
    local detail = mode_details[status]
    if detail then
        detail = str_fmt(detail, help_url)
    end

    if status == 429 then
        local reset = ngx.header["X-RateLimit-Reset"]
        detail = "Request quota exhausted."
        if reset then
            detail = detail .. " Retry in " .. tostring(reset) .. " seconds; "
                  .. "X-RateLimit-Reset carries the remaining window."
        end
    elseif status == 502 or status == 503 or status == 504 then
        detail = conf.service_name .. " did not respond. The gateway is up; retry shortly."
    end

    return core.json.encode({
        error   = CODES[status] or "error",
        status  = status,
        detail  = detail or "The gateway refused this request.",
        service = conf.service_name,
        help    = conf.portal_url ~= "" and conf.portal_url or nil,
        docs    = conf.docs_url ~= "" and conf.docs_url or nil,
    })
end


-- ---------------------------------------------------------------------------
-- Phases
-- ---------------------------------------------------------------------------

function _M.header_filter(conf, ctx)
    local status = ngx.status
    if status < 400 then
        return
    end

    local handled = RENDERERS[status] ~= nil
                    or status == 502 or status == 503 or status == 504

    if wants_html(ctx) then
        if not handled then
            return      -- 404s and anything else keep the upstream's own body
        end
        local render = RENDERERS[status]
        ctx.friendly_body = render and render(conf, ctx)
                            or upstream_down(conf, ctx, status)
        ngx.header["Content-Type"] = "text/html; charset=utf-8"
    else
        -- The client wants anything but HTML. Only step in when the body would
        -- otherwise be HTML — which is what nginx supplies when a plugin exits
        -- without writing one.
        local content_type = ngx.header["Content-Type"]
        if not content_type or not core.string.find(content_type, "text/html") then
            return
        end
        ctx.friendly_body = machine_readable(conf, ctx, status)
        ngx.header["Content-Type"] = "application/json; charset=utf-8"
    end

    ngx.header["Content-Length"] = nil     -- the replacement body is a different length
    ngx.header["Cache-Control"]  = "no-store"
end


function _M.body_filter(conf, ctx)
    if not ctx.friendly_body then
        return
    end
    if ctx.friendly_sent then
        -- Swallow whatever the original body still had to say.
        ngx.arg[1] = ""
        return
    end
    ngx.arg[1] = ctx.friendly_body
    ngx.arg[2] = true          -- this is the last chunk
    ctx.friendly_sent = true
end


return _M
