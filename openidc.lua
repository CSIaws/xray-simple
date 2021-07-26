local require = require
local cjson = require("cjson")
local cjson_s = require("cjson.safe")
local http = require("resty.http")
local r_session = require("resty.session")
local string = string
local ipairs = ipairs
local pairs = pairs
local type = type
local ngx = ngx
local b64 = ngx.encode_base64
local unb64 = ngx.decode_base64

local log = ngx.log
local DEBUG = ngx.DEBUG
local INFO = ngx.INFO
local ERROR = ngx.ERR
local WARN = ngx.WARN

local openidc = {
  _VERSION = "1.7.4"
}
openidc.__index = openidc

local function store_in_session(opts, feature)
  -- We don't have a whitelist of features to enable
  if not opts.session_contents then
    return true
  end

  return opts.session_contents[feature]
end

-- set value in server-wide cache if available
local function openidc_cache_set(type, key, value, exp)
  local dict = ngx.shared[type]
  if dict and (exp > 0) then
    local success, err, forcible = dict:set(key, value, exp)
    log(DEBUG, "cache set: success=", success, " err=", err, " forcible=", forcible)
  end
end

-- retrieve value from server-wide cache if available
local function openidc_cache_get(type, key)
  local dict = ngx.shared[type]
  local value
  if dict then
    value = dict:get(key)
    if value then log(DEBUG, "cache hit: type=", type, " key=", key) end
  end
  return value
end

-- invalidate values of server-wide cache
local function openidc_cache_invalidate(type)
  local dict = ngx.shared[type]
  if dict then
    log(DEBUG, "flushing cache for " .. type)
    dict.flush_all(dict)
    local nbr = dict.flush_expired(dict)
  end
end

-- invalidate all server-wide caches
function openidc.invalidate_caches()
  openidc_cache_invalidate("discovery")
  openidc_cache_invalidate("jwks")
  openidc_cache_invalidate("introspection")
end

-- validate the contents of and id_token
local function openidc_validate_id_token(opts, id_token, nonce)

  -- check issuer
  if opts.discovery.issuer ~= id_token.iss then
    log(ERROR, "issuer \"", id_token.iss, "\" in id_token is not equal to the issuer from the discovery document \"", opts.discovery.issuer, "\"")
    return false
  end

  -- check sub
  if not id_token.sub then
    log(ERROR, "no \"sub\" claim found in id_token")
    return false
  end

  -- check nonce
  if nonce and nonce ~= id_token.nonce then
    log(ERROR, "nonce \"", id_token.nonce, "\" in id_token is not equal to the nonce that was sent in the request \"", nonce, "\"")
    return false
  end

  -- check issued-at timestamp
  if not id_token.iat then
    log(ERROR, "no \"iat\" claim found in id_token")
    return false
  end

  local slack = opts.iat_slack and opts.iat_slack or 120
  if id_token.iat > (ngx.time() + slack) then
    log(ERROR, "id_token not yet valid: id_token.iat=", id_token.iat, ", ngx.time()=", ngx.time(), ", slack=", slack)
    return false
  end

  -- check expiry timestamp
  if not id_token.exp then
    log(ERROR, "no \"exp\" claim found in id_token")
    return false
  end

  if (id_token.exp + slack) < ngx.time() then
    log(ERROR, "token expired: id_token.exp=", id_token.exp, ", ngx.time()=", ngx.time())
    return false
  end

  -- check audience (array or string)
  if not id_token.aud then
    log(ERROR, "no \"aud\" claim found in id_token")
    return false
  end

  if (type(id_token.aud) == "table") then
    for _, value in pairs(id_token.aud) do
      if value == opts.client_id then
        return true
      end
    end
    log(ERROR, "no match found token audience array: client_id=", opts.client_id)
    return false
  elseif (type(id_token.aud) == "string") then
    if id_token.aud ~= opts.client_id then
      log(ERROR, "token audience does not match: id_token.aud=", id_token.aud, ", client_id=", opts.client_id)
      return false
    end
  end
  return true
end

local function get_first(table_or_string)
  local res = table_or_string
  if table_or_string and type(table_or_string) == 'table' then
    res = table_or_string[1]
  end
  return res
end

local function get_first_header(headers, header_name)
  local header = headers[header_name]
  return get_first(header)
end

local function get_first_header_and_strip_whitespace(headers, header_name)
  local header = get_first_header(headers, header_name)
  return header and header:gsub('%s', '')
end

local function get_forwarded_parameter(headers, param_name)
  local forwarded = get_first_header(headers, 'Forwarded')
  local params = {}
  if forwarded then
    local function parse_parameter(pv)
      local name, value = pv:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
      if name and value then
        if value:sub(1, 1) == '"' then
          value = value:sub(2, -2)
        end
        params[name:lower()] = value
      end
    end

    -- this assumes there is no quoted comma inside the header's value
    -- which should be fine as comma is not legal inside a node name,
    -- a URI scheme or a host name. The only thing that might bite us
    -- are extensions.
    local first_part = forwarded
    local first_comma = forwarded:find("%s*,%s*")
    if first_comma then
      first_part = forwarded:sub(1, first_comma - 1)
    end
    first_part:gsub("[^;]+", parse_parameter)
  end
  return params[param_name:gsub("^%s*(.-)%s*$", "%1"):lower()]
end

local function get_scheme(headers)
  return get_forwarded_parameter(headers, 'proto')
      or get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Proto')
      or ngx.var.scheme
end

local function get_host_name_from_x_header(headers)
  local header = get_first_header_and_strip_whitespace(headers, 'X-Forwarded-Host')
  return header and header:gsub('^([^,]+),?.*$', '%1')
end

local function get_host_name(headers)
  return get_forwarded_parameter(headers, 'host')
      or get_host_name_from_x_header(headers)
      or ngx.var.http_host
end

-- perform base64url decoding
local function openidc_base64_url_decode(input)
  local reminder = #input % 4
  if reminder > 0 then
    local padlen = 4 - reminder
    input = input .. string.rep('=', padlen)
  end
  input = input:gsub('%-', '+'):gsub('_', '/')
  return unb64(input)
end

-- perform base64url encoding
local function openidc_base64_url_encode(input)
  local output = b64(input, true)
  return output:gsub('%+', '-'):gsub('/', '_')
end

local function openidc_combine_uri(uri, params)
  if params == nil or next(params) == nil then
    return uri
  end
  local sep = "?"
  if string.find(uri, "?", 1, true) then
    sep = "&"
  end
  return uri .. sep .. ngx.encode_args(params)
end

local function decorate_request(http_request_decorator, req)
  return http_request_decorator and http_request_decorator(req) or req
end

local function openidc_s256(verifier)
  local sha256 = (require 'resty.sha256'):new()
  sha256:update(verifier)
  return openidc_base64_url_encode(sha256:final())
end

-- send the browser of to the OP's authorization endpoint
local function openidc_authorize(opts, session, target_url, prompt)
  local resty_random = require("resty.random")
  local resty_string = require("resty.string")

  -- generate state and nonce
  local state = resty_string.to_hex(resty_random.bytes(16))
  local nonce = resty_string.to_hex(resty_random.bytes(16))
  local code_verifier = openidc_base64_url_encode(resty_random.bytes(32))

  -- assemble the parameters to the authentication request
  local params = {
    client_id = opts.client_id,
    response_type = "code",
    scope = opts.scope and opts.scope or "openid",
    redirect_uri = opts.redirect_uri,
    state = state,
  }

  if nonce then
    params.nonce = nonce
  end

  if prompt then
    params.prompt = prompt
  end

  if opts.display then
    params.display = opts.display
  end

  if code_verifier then
    params.code_challenge_method = 'S256'
    params.code_challenge = openidc_s256(code_verifier)
  end

  -- merge any provided extra parameters
  if opts.authorization_params then
    for k, v in pairs(opts.authorization_params) do params[k] = v end
  end

  -- store state in the session
  session.data.original_url = target_url
  session.data.state = state
  session.data.nonce = nonce
  session.data.code_verifier = code_verifier
  session.data.last_authenticated = ngx.time()

  session:save()

  -- redirect to the /authorization endpoint
  log(INFO, "Authorization Request")
  ngx.header["Cache-Control"] = "no-cache, no-store, max-age=0"
  return ngx.redirect(openidc_combine_uri(opts.discovery.authorization_endpoint, params))
end

-- parse the JSON result from a call to the OP
local function openidc_parse_json_response(response)
  local err
  local res

  -- check the response from the OP
  if response.status ~= 200 then
    err = "response indicates failure, status=" .. response.status .. ", body=" .. response.body
  end

  -- decode the response and extract the JSON object
  res = cjson_s.decode(response.body)

  if not res and not err then
    err = "JSON decoding failed"
  end

  return res, err
end

local function openidc_configure_timeouts(httpc, timeout)
  if timeout then
    if type(timeout) == "table" then
      local r, e = httpc:set_timeouts(timeout.connect or 0, timeout.send or 0, timeout.read or 0)
    else
      local r, e = httpc:set_timeout(timeout)
    end
  end
end

-- Set outgoing proxy options
local function openidc_configure_proxy(httpc, proxy_opts)
  if httpc and proxy_opts and type(proxy_opts) == "table" then
    log(DEBUG, "openidc_configure_proxy : use http proxy")
    httpc:set_proxy_options(proxy_opts)
  else
    log(DEBUG, "openidc_configure_proxy : don't use http proxy")
  end
end

-- make a call to the token endpoint
function openidc.call_token_endpoint(opts, endpoint, body)
  local ep_name = 'token'
  if not endpoint then
    return nil, 'no endpoint URI for ' .. ep_name
  end

  local headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded"
  }

  headers.Authorization = "Basic " .. b64(ngx.escape_uri(opts.client_id) .. ":" .. ngx.escape_uri(opts.client_secret))
  log(DEBUG, "client_secret_basic: authorization header '" .. headers.Authorization .. "'")

  log(DEBUG, "request body for " .. ep_name .. " endpoint call: ", ngx.encode_args(body))

  local httpc = http.new()
  openidc_configure_timeouts(httpc, opts.timeout)
  openidc_configure_proxy(httpc, opts.proxy_opts)
  local res, err = httpc:request_uri(endpoint, decorate_request(opts.http_request_decorator, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = headers,
    ssl_verify = (opts.ssl_verify ~= "no"),
    keepalive = (opts.keepalive ~= "no")
  }))
  if not res then
    err = "accessing " .. ep_name .. " endpoint (" .. endpoint .. ") failed: " .. err
    log(ERROR, err)
    return nil, err
  end

  log(DEBUG, ep_name .. " endpoint response: ", res.body)

  return openidc_parse_json_response(res)
end

-- computes access_token expires_in value (in seconds)
local function openidc_access_token_expires_in(opts, expires_in)
  return (expires_in or opts.access_token_expires_in or 3600) - 1 - (opts.access_token_expires_leeway or 0)
end

-- turn a discovery url set in the opts dictionary into the discovered information
local function openidc_ensure_discovered_data(opts)
  opts.discovery = {}
  opts.discovery.issuer = opts.issuer
  opts.discovery.authorization_endpoint = opts.authorization_endpoint
  opts.discovery.token_endpoint = opts.token_endpoint
  opts.discovery.jwks_uri = opts.jwks_uri
  opts.discovery.end_session_endpoint = opts.end_session_endpoint
  opts.discovery.id_token_signing_alg_values_supported = {'RS256'}
  return nil
end

-- ensure that discovery and token auth configuration is available in opts
local function ensure_config(opts)
  local err
  err = openidc_ensure_discovered_data(opts)
  if err then
    return err
  end
end

local function openidc_jwks(url, force, ssl_verify, keepalive, timeout, exptime, proxy_opts, http_request_decorator)
  log(DEBUG, "openidc_jwks: URL is: " .. url .. " (force=" .. force .. ") (decorator=" .. (http_request_decorator and type(http_request_decorator) or "nil"))

  local json, err, v

  if force == 0 then
    v = openidc_cache_get("jwks", url)
  end

  if not v then

    log(DEBUG, "cannot use cached JWKS data; making call to jwks endpoint")
    -- make the call to the jwks endpoint
    log(INFO, "Call jwks_uri")
    local httpc = http.new()
    openidc_configure_timeouts(httpc, timeout)
    openidc_configure_proxy(httpc, proxy_opts)
    local res, error = httpc:request_uri(url, decorate_request(http_request_decorator, {
      ssl_verify = (ssl_verify ~= "no"),
      keepalive = (keepalive ~= "no")
    }))
    if not res then
      err = "accessing jwks url (" .. url .. ") failed: " .. error
      log(ERROR, err)
    else
      log(DEBUG, "response data: " .. res.body)
      json, err = openidc_parse_json_response(res)
      if json and not err then
        openidc_cache_set("jwks", url, cjson.encode(json), exptime or 24 * 60 * 60)
      end
    end

  else
    json = cjson.decode(v)
  end

  return json, err
end

local function split_by_chunk(text, chunkSize)
  local s = {}
  for i = 1, #text, chunkSize do
    s[#s + 1] = text:sub(i, i + chunkSize - 1)
  end
  return s
end

local function get_jwk(keys, kid)

  local rsa_keys = {}
  for _, value in pairs(keys) do
    if value.kty == "RSA" and (not value.use or value.use == "sig") then
      table.insert(rsa_keys, value)
    end
  end

  if kid == nil then
    if #rsa_keys == 1 then
      log(DEBUG, "returning only RSA key of JWKS for keyid-less JWT")
      return rsa_keys[1], nil
    else
      return nil, "JWT doesn't specify kid but the keystore contains multiple RSA keys"
    end
  end
  for _, value in pairs(rsa_keys) do
    if value.kid == kid then
      return value, nil
    end
  end

  return nil, "RSA key with id " .. kid .. " not found"
end

local wrap = ('.'):rep(64)

local envelope = "-----BEGIN %s-----\n%s\n-----END %s-----\n"

local function der2pem(data, typ)
  typ = typ:upper() or "CERTIFICATE"
  data = b64(data)
  return string.format(envelope, typ, data:gsub(wrap, '%0\n', (#data - 1) / 64), typ)
end


local function encode_length(length)
  if length < 0x80 then
    return string.char(length)
  elseif length < 0x100 then
    return string.char(0x81, length)
  elseif length < 0x10000 then
    return string.char(0x82, math.floor(length / 0x100), length % 0x100)
  end
  error("Can't encode lengths over 65535")
end

local function encode_sequence(array, of)
  local encoded_array = array
  if of then
    encoded_array = {}
    for i = 1, #array do
      encoded_array[i] = of(array[i])
    end
  end
  encoded_array = table.concat(encoded_array)

  return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array
end

local function encode_binary_integer(bytes)
  if bytes:byte(1) > 127 then
    -- We currenly only use this for unsigned integers,
    -- however since the high bit is set here, it would look
    -- like a negative signed int, so prefix with zeroes
    bytes = "\0" .. bytes
  end
  return "\2" .. encode_length(#bytes) .. bytes
end

local function encode_sequence_of_integer(array)
  return encode_sequence(array, encode_binary_integer)
end

local function encode_bit_string(array)
  local s = "\0" .. array -- first octet holds the number of unused bits
  return "\3" .. encode_length(#s) .. s
end

local function openidc_pem_from_x5c(x5c)
  -- TODO check x5c length
  log(DEBUG, "Found x5c, getting PEM public key from x5c entry of json public key")
  local chunks = split_by_chunk(b64(openidc_base64_url_decode(x5c[1])), 64)
  local pem = "-----BEGIN CERTIFICATE-----\n" ..
      table.concat(chunks, "\n") ..
      "\n-----END CERTIFICATE-----"
  log(DEBUG, "Generated PEM key from x5c:", pem)
  return pem
end

local function openidc_pem_from_rsa_n_and_e(n, e)
  log(DEBUG, "getting PEM public key from n and e parameters of json public key")

  local der_key = {
    openidc_base64_url_decode(n), openidc_base64_url_decode(e)
  }
  local encoded_key = encode_sequence_of_integer(der_key)
  local pem = der2pem(encode_sequence({
    encode_sequence({
      "\6\9\42\134\72\134\247\13\1\1\1" -- OID :rsaEncryption
          .. "\5\0" -- ASN.1 NULL of length 0
    }),
    encode_bit_string(encoded_key)
  }), "PUBLIC KEY")
  log(DEBUG, "Generated pem key from n and e: ", pem)
  return pem
end

local function openidc_pem_from_jwk(opts, kid)
  local err = openidc_ensure_discovered_data(opts)
  if err then
    return nil, err
  end

  if not opts.discovery.jwks_uri or not (type(opts.discovery.jwks_uri) == "string") or (opts.discovery.jwks_uri == "") then
    return nil, "opts.discovery.jwks_uri is not present or not a string"
  end

  local cache_id = opts.discovery.jwks_uri .. '#' .. (kid or '')
  local v = openidc_cache_get("jwks", cache_id)

  if v then
    return v
  end

  local jwk, jwks

  for force = 0, 1 do
    jwks, err = openidc_jwks(opts.discovery.jwks_uri, force, opts.ssl_verify, opts.keepalive, opts.timeout, opts.jwk_expires_in, opts.proxy_opts,
                             opts.http_request_decorator)
    if err then
      return nil, err
    end

    jwk, err = get_jwk(jwks.keys, kid)

    if jwk and not err then
      break
    end
  end

  if err then
    return nil, err
  end

  local pem
  -- TODO check x5c length
  if jwk.x5c then
    pem = openidc_pem_from_x5c(jwk.x5c)
  elseif jwk.kty == "RSA" and jwk.n and jwk.e then
    pem = openidc_pem_from_rsa_n_and_e(jwk.n, jwk.e)
  else
    return nil, "don't know how to create RSA key/cert for " .. cjson.encode(jwk)
  end

  openidc_cache_set("jwks", cache_id, pem, opts.jwk_expires_in or 24 * 60 * 60)
  return pem
end

-- does lua-resty-jwt and/or we know how to handle the algorithm of the JWT?
local function is_algorithm_supported(jwt_header)
  return jwt_header and jwt_header.alg and string.sub(jwt_header.alg, 1, 2) == "RS"
end

-- is the JWT signing algorithm an asymmetric one whose key might be
-- obtained from the discovery endpoint?
local function uses_asymmetric_algorithm(jwt_header)
  return string.sub(jwt_header.alg, 1, 2) == "RS"
end

-- is the JWT signing algorithm one that has been expected?
local function is_algorithm_expected(jwt_header, expected_algs)
  if expected_algs == nil or not jwt_header or not jwt_header.alg then
    return true
  end
  if type(expected_algs) == 'string' then
    expected_algs = { expected_algs }
  end
  for _, alg in ipairs(expected_algs) do
    if alg == jwt_header.alg then
      return true
    end
  end
  return false
end

-- parse a JWT and verify its signature (if present)
local function openidc_load_jwt_and_verify_crypto(opts, jwt_string, asymmetric_secret,
symmetric_secret, expected_algs, ...)
  local r_jwt = require("resty.jwt")
  local enc_hdr, enc_payload, enc_sign = string.match(jwt_string, '^(.+)%.(.+)%.(.*)$')

  local jwt_obj = r_jwt:load_jwt(jwt_string, nil)
  if not jwt_obj.valid then
    local reason = "invalid jwt"
    if jwt_obj.reason then
      reason = reason .. ": " .. jwt_obj.reason
    end
    return nil, reason
  end

  if not is_algorithm_expected(jwt_obj.header, expected_algs) then
    local alg = jwt_obj.header and jwt_obj.header.alg or "no algorithm at all"
    return nil, "token is signed by unexpected algorithm \"" .. alg .. "\""
  end

  local secret
  if is_algorithm_supported(jwt_obj.header) then
    if uses_asymmetric_algorithm(jwt_obj.header) then
      if opts.secret then
        log(WARN, "using deprecated option `opts.secret` for asymmetric key; switch to `opts.public_key` instead")
      end
      secret = asymmetric_secret or opts.secret
      if not secret and opts.discovery then
        log(DEBUG, "using discovery to find key")
        local err
        secret, err = openidc_pem_from_jwk(opts, jwt_obj.header.kid)

        if secret == nil then
          log(ERROR, err)
          return nil, err
        end
      end
    end
  end

  if #{ ... } == 0 then
    -- an empty list of claim specs makes lua-resty-jwt add default
    -- validators for the exp and nbf claims if they are
    -- present. These validators need to know the configured slack
    -- value
    local jwt_validators = require("resty.jwt-validators")
    jwt_validators.set_system_leeway(opts.iat_slack and opts.iat_slack or 120)
  end

  jwt_obj = r_jwt:verify_jwt_obj(secret, jwt_obj, ...)
  if jwt_obj then
    log(DEBUG, "jwt: ", cjson.encode(jwt_obj), " ,valid: ", jwt_obj.valid, ", verified: ", jwt_obj.verified)
  end
  if not jwt_obj.verified then
    local reason = "jwt signature verification failed"
    if jwt_obj.reason then
      reason = reason .. ": " .. jwt_obj.reason
    end
    return jwt_obj, reason
  end
  return jwt_obj
end

--
-- Load and validate id token from the id_token properties of the token endpoint response
-- Parameters :
--     - opts the openidc module options
--     - jwt_id_token the id_token from the id_token properties of the token endpoint response
--     - session the current session
-- Return the id_token, nil if valid
-- Return nil, the error if invalid
--
local function openidc_load_and_validate_jwt_id_token(opts, jwt_id_token, session)

  local jwt_obj, err = openidc_load_jwt_and_verify_crypto(opts, jwt_id_token, opts.public_key, opts.client_secret,
    opts.discovery.id_token_signing_alg_values_supported)
  if err then
    local alg = (jwt_obj and jwt_obj.header and jwt_obj.header.alg) or ''
    local is_unsupported_signature_error = jwt_obj and not jwt_obj.verified and not is_algorithm_supported(jwt_obj.header)
    if is_unsupported_signature_error then
      if opts.accept_unsupported_alg == nil or opts.accept_unsupported_alg then
        log(WARN, "ignored id_token signature as algorithm '" .. alg .. "' is not supported")
      else
        err = "token is signed using algorithm \"" .. alg .. "\" which is not supported by lua-resty-jwt"
        log(ERROR, err)
        return nil, err
      end
    else
      log(ERROR, "id_token '" .. alg .. "' signature verification failed")
      return nil, err
    end
  end
  local id_token = jwt_obj.payload

  log(DEBUG, "id_token header: ", cjson.encode(jwt_obj.header))
  log(DEBUG, "id_token payload: ", cjson.encode(jwt_obj.payload))

  -- validate the id_token contents
  if openidc_validate_id_token(opts, id_token, session.data.nonce) == false then
    err = "id_token validation failed"
    log(ERROR, err)
    return nil, err
  end

  return id_token
end

-- handle a "code" authorization response from the OP
local function openidc_authorization_response(opts, session)
  local args = ngx.req.get_uri_args()
  local err, log_err, client_err

  if not args.code or not args.state then
    err = "unhandled request to the redirect_uri: " .. ngx.var.request_uri
    log(ERROR, err)
    return nil, err, session.data.original_url, session
  end

  -- check that the state returned in the response against the session; prevents CSRF
  if args.state ~= session.data.state then
    log_err = "state from argument: " .. (args.state and args.state or "nil") .. " does not match state restored from session: " .. (session.data.state and session.data.state or "nil")
    client_err = "state from argument does not match state restored from session"
    log(ERROR, log_err)
    return nil, client_err, session.data.original_url, session
  end

  err = ensure_config(opts)
  if err then
    return nil, err, session.data.original_url, session
  end

  -- assemble the parameters to the token endpoint
  local body = {
    grant_type = "authorization_code",
    code = args.code,
    redirect_uri = opts.redirect_uri,
    code_verifier = session.data.code_verifier
  }

  log(DEBUG, "Authentication with OP done -> Calling OP Token Endpoint to obtain tokens")

  local current_time = ngx.time()
  -- make the call to the token endpoint
  log(INFO, "Token Request")
  local json
  json, err = openidc.call_token_endpoint(opts, opts.discovery.token_endpoint, body)
  if err then
    return nil, err, session.data.original_url, session
  end

  local id_token, err = openidc_load_and_validate_jwt_id_token(opts, json.id_token, session);
  if err then
    return nil, err, session.data.original_url, session
  end

  -- mark this sessions as authenticated
  session.data.authenticated = true
  -- clear state, nonce and code_verifier to protect against potential misuse
  session.data.nonce = nil
  session.data.state = nil
  session.data.code_verifier = nil
  if store_in_session(opts, 'id_token') then
    session.data.id_token = id_token
  end

  if store_in_session(opts, 'access_token') then
    session.data.access_token = json.access_token
    session.data.access_token_expiration = current_time
        + openidc_access_token_expires_in(opts, json.expires_in)
    if json.refresh_token ~= nil then
      session.data.refresh_token = json.refresh_token
    end
  end

  -- save the session with the obtained id_token
  session:save()

  -- redirect to the URL that was accessed originally
  log(DEBUG, "OIDC Authorization Code Flow completed -> Redirecting to original URL (" .. session.data.original_url .. ")")
  ngx.redirect(session.data.original_url)
  return nil, nil, session.data.original_url, session
end

local openidc_transparent_pixel = "\137\080\078\071\013\010\026\010\000\000\000\013\073\072\068\082" ..
    "\000\000\000\001\000\000\000\001\008\004\000\000\000\181\028\012" ..
    "\002\000\000\000\011\073\068\065\084\120\156\099\250\207\000\000" ..
    "\002\007\001\002\154\028\049\113\000\000\000\000\073\069\078\068" ..
    "\174\066\096\130"

-- handle logout
local function openidc_logout(opts, session)
  local refresh_token = session.data.refresh_token

  session:destroy()

  local endpoint = opts.discovery.end_session_endpoint
  local headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded",
    ["Authorization"] = "Basic " .. b64(ngx.escape_uri(opts.client_id) .. ":" .. ngx.escape_uri(opts.client_secret))
  }
  local body = {
    refresh_token = refresh_token
  }

  log(INFO, "Logout Request")
  local httpc = http.new()
  openidc_configure_timeouts(httpc, opts.timeout)
  openidc_configure_proxy(httpc, opts.proxy_opts)
  local res, err = httpc:request_uri(endpoint, decorate_request(opts.http_request_decorator, {
    method = "POST",
    body = ngx.encode_args(body),
    headers = headers,
    ssl_verify = (opts.ssl_verify ~= "no"),
    keepalive = (opts.keepalive ~= "no")
  }))
  if not res then
    err = "accessing logout endpoint (" .. endpoint .. ") failed: " .. err
    log(ERROR, err)
  end

  ngx.header.content_type = "text/html"
  ngx.say("<html><body>Logged Out</body></html>")
  ngx.exit(ngx.OK)
end

-- returns a valid access_token (eventually refreshing the token)
local function openidc_access_token(opts, session)

  local err

  if session.data.access_token == nil then
    return nil, err
  end
  local current_time = ngx.time()
  if current_time < session.data.access_token_expiration then
    return session.data.access_token, err
  end

  if session.data.refresh_token == nil then
    return nil, "token expired and no refresh token available"
  end

  log(DEBUG, "refreshing expired access_token: ", session.data.access_token, " with: ", session.data.refresh_token)

  -- retrieve token endpoint URL from discovery endpoint if necessary
  err = ensure_config(opts)
  if err then
    return nil, err
  end

  -- assemble the parameters to the token endpoint
  local body = {
    grant_type = "refresh_token",
    refresh_token = session.data.refresh_token,
    scope = opts.scope and opts.scope or "openid"
  }

  log(INFO, "Token Refresh")
  local json
  json, err = openidc.call_token_endpoint(opts, opts.discovery.token_endpoint, body)
  if err then
    return json, err
  end
  local id_token
  if json.id_token then
    id_token, err = openidc_load_and_validate_jwt_id_token(opts, json.id_token, session)
    if err then
      log(ERROR, "invalid id token, discarding tokens returned while refreshing")
      return nil, err
    end
  end
  log(DEBUG, "access_token refreshed: ", json.access_token, " updated refresh_token: ", json.refresh_token)

  session.data.access_token = json.access_token
  session.data.access_token_expiration = current_time + openidc_access_token_expires_in(opts, json.expires_in)
  if json.refresh_token then
    session.data.refresh_token = json.refresh_token
  end

  if json.id_token and store_in_session(opts, 'id_token') then
    log(DEBUG, "id_token refreshed: ", json.id_token)
    if store_in_session(opts, 'id_token') then
      session.data.id_token = id_token
    end
  end

  -- save the session with the new access_token and optionally the new refresh_token and id_token using a new sessionid
  local regenerated
  regenerated, err = session:regenerate()
  if err then
    log(ERROR, "failed to regenerate session: " .. err)
    return nil, err
  end

  return session.data.access_token, err
end

local function openidc_get_path(uri)
  local without_query = uri:match("(.-)%?") or uri
  return without_query:match(".-//[^/]+(/.*)") or without_query
end

local function openidc_get_redirect_uri_path(opts)
  return opts.redirect_uri and openidc_get_path(opts.redirect_uri) or opts.redirect_uri_path
end

-- main routine for OpenID Connect user authentication
function openidc.authenticate(opts, session_opts)

  if opts.redirect_uri_path then
    log(WARN, "using deprecated option `opts.redirect_uri_path`; switch to using an absolute URI and `opts.redirect_uri` instead")
  end

  local err

  local session, session_error = r_session.start(session_opts)
  if session == nil then
    log(ERROR, "Error starting session: " .. session_error)
    return nil, session_error, opts.target_url, session
  end

  local target_url = opts.target_url or ngx.var.request_uri

  local access_token

  -- see if this is a request to the redirect_uri i.e. an authorization response
  local path = openidc_get_path(ngx.var.request_uri)
  if path == openidc_get_redirect_uri_path(opts) then
    log(DEBUG, "Redirect URI path (" .. path .. ") is currently navigated -> Processing authorization response coming from OP")

    if not session.present then
      err = "request to the redirect_uri path but there's no session state found"
      log(ERROR, err)
      return nil, err, ngx.var.request_uri, session
    end

    return openidc_authorization_response(opts, session)
  end

  -- see if this is a request to logout
  if path == (opts.logout_path or "/logout") then
    log(DEBUG, "Logout path (" .. path .. ") is currently navigated -> Processing local session removal before redirecting to next step of logout process")

    err = ensure_config(opts)
    if err then
      return nil, err, session.data.original_url, session
    end

    openidc_logout(opts, session)
    return nil, nil, ngx.var.request_uri, session
  end

  local token_expired = false
  if session.present and session.data.authenticated
      and store_in_session(opts, 'access_token') then

    -- refresh access_token if necessary
    access_token, err = openidc_access_token(opts, session)
    if err then
      if access_token.error_description == "Token is not active" then
        access_token = nil
      else
        log(ERROR, "lost access token:" .. err)
      end
      err = nil
    end
    if not access_token then
      token_expired = true
    end
  end

  log(DEBUG,
    "session.present=", session.present,
    ", session.data.id_token=", session.data.id_token ~= nil,
    ", session.data.authenticated=", session.data.authenticated,
    ", opts.force_reauthorize=", opts.force_reauthorize,
    ", opts.renew_access_token_on_expiry=", opts.renew_access_token_on_expiry,
    ", token_expired=", token_expired)

  -- if we are not authenticated then redirect to the OP for authentication
  -- the presence of the id_token is check for backwards compatibility
  if not session.present
      or not (session.data.id_token or session.data.authenticated)
      or opts.force_reauthorize
      or token_expired then

    err = ensure_config(opts)
    if err then
      return nil, err, session.data.original_url, session
    end

    log(DEBUG, "Authentication is required - Redirecting to OP Authorization endpoint")
    openidc_authorize(opts, session, target_url, opts.prompt)
    return nil, nil, ngx.var.request_uri, session
  end

  if store_in_session(opts, 'id_token') then
    -- log id_token contents
    log(DEBUG, "id_token=", cjson.encode(session.data.id_token))
  end

  -- return the id_token to the caller Lua script for access control purposes
  return
  {
    id_token = session.data.id_token,
    access_token = access_token,
    user = session.data.user
  },
  err,
  target_url,
  session
end

-- Passing nil to any of the arguments resets the configuration to default
function openidc.set_logging(new_log, new_levels)
  log = new_log and new_log or ngx.log
  DEBUG = new_levels.DEBUG and new_levels.DEBUG or ngx.DEBUG
  ERROR = new_levels.ERROR and new_levels.ERROR or ngx.ERR
  WARN = new_levels.WARN and new_levels.WARN or ngx.WARN
end

return openidc

