##
# GrantedByMe Ruby SDK
# author: GrantedByMe <info@grantedby.me>
#

class GrantedByMe

  VERSION = '1.0.6'
  BRANCH = 'master'
  HOST = 'https://api.grantedby.me/v1/service/'
  USER_AGENT = 'GrantedByMe/' + VERSION + '-' + BRANCH + ' (Ruby)'

  ##
  # Constructor
  #
  def initialize(private_key, server_key)
    @crypto = Crypto.new
    @server_key = server_key
    @private_key = private_key
    @api_url = HOST
    if server_key
      @public_hash = Crypto.digest(server_key)
    end
  end

  ########################################
  # Getters / Setters
  ########################################

  ##
  # Returns the Service RSA public key in serialized PEM string format
  #
  def get_private_key
    return @private_key
  end

  ##
  # Returns the Service RSA public key in serialized PEM string format
  #
  def get_public_key
    private_rsa = OpenSSL::PKey::RSA.new @private_key
    return private_rsa.public_key.to_pem
  end

  ##
  # Returns the Server RSA public key in serialized PEM string format
  #
  def get_server_key
    return @server_key
  end

  ##
  # Returns the crypto helper reference
  #
  def get_crypto
    return @crypto
  end

  ##
  # Returns a random string with length
  #
  def get_random_string(length)
    return Base64.strict_encode64(OpenSSL::Random.random_bytes(length))
  end

  ########################################
  # API
  ########################################

  ##
  # RSA key exchange
  #
  def activate_handshake(public_key)
    params = {}
    params['public_key'] = public_key
    params['timestamp'] = Time.now.to_i
    url = @api_url + 'activate_handshake' + '/'
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Post.new(uri.path, initheader = {'Content-Type' => 'application/json'})
    request.body = params.to_json
    response = http.request(request)
    return JSON.parse(response.body)
    rescue => e
      puts "failed: #{e}"
      return nil
  end

  ##
  # Service activation
  #
  def activate_service(service_key)
    if @private_key == nil
      key = OpenSSL::PKey::RSA.new 2048
      @private_key = key.to_pem
    end
    if @server_key == nil
      handshake = activate_handshake(key.public_key.to_pem)
      if handshake && handshake['success'] && handshake['public_key']
        @server_key = handshake['public_key']
        @public_hash = Crypto.digest(@server_key)
      else
        raise 'Handshake failed'
      end
    end
    params = get_params()
    params['grantor'] = get_random_string(128)
    params['service_key'] = service_key
    post(params, 'activate_service')
  end

  ##
  # Service deactivation
  #
  def deactivate_service
    params = get_params()
    post(params, 'deactivate_service')
  end

  ##
  # Link a user service account
  #
  def link_account(token, grantor)
    params = get_params()
    params['token'] = token
    params['grantor'] = grantor
    post(params, 'link_account')
  end

  ##
  # Unlink a user service account
  #
  def unlink_account(grantor)
    params = get_params()
    params['grantor'] = Crypto.digest(grantor)
    post(params, 'unlink_account')
  end

  ##
  # Retrieve an account link token
  #
  def get_account_token()
    get_token(1)
  end

  ##
  # Retrieve a session link token
  #
  def get_session_token()
    get_token(2)
  end

  ##
  # Retrieve a session link token
  #
  def get_register_token()
    get_token(4)
  end

  ##
  # Retrieve a session link token
  #
  def get_token(type, client_ip=nil, client_ua=nil)
    params = get_params()
    params['token_type'] = type
    if client_ua
        params['http_user_agent'] = client_ua
    end
    if client_ip
      params['remote_addr'] = client_ip
    end
    post(params, 'get_session_token')
  end

  ##
  # Retrieve a session link token state
  #
  def get_token_state(token, client_ip=nil, client_ua=nil)
    params = get_params()
    params['token'] = token
    if client_ua
      params['http_user_agent'] = client_ua
    end
    if client_ip
      params['remote_addr'] = client_ip
    end
    post(params, 'get_session_state')
  end

  ########################################
  # HELPERS
  ########################################

  ##
  # Assembles default POST request parameters
  #
  def get_params()
    params = {}
    params['timestamp'] = Time.now.to_i
    params
  end

  ##
  # Sends a POST JSON request
  #
  def post(params, operation)
    # puts("post: #{params}")
    url = @api_url + operation + '/'
    uri = URI(url)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Post.new(uri.path, initheader = {'Content-Type' => 'application/json', 'User-Agent' => USER_AGENT})
    if uri.scheme == 'https'
      http.use_ssl = true
      http.ssl_version = :TLSv1_2
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    end
    encrypted_params = @crypto.encrypt(params, @private_key, @server_key)
    encrypted_params['public_hash'] = @public_hash
    request.body = encrypted_params.to_json
    response = http.request(request)
    result = JSON.parse(response.body)
    if result['payload']
      return @crypto.decrypt(result, @private_key, @server_key)
    end
    return result
    rescue => e
      puts "http post failed: #{e}"
      return '{"success": false}'
  end

end

require 'date'
require 'json'
require 'net/http'
require 'grantedbyme/crypto'
require 'openssl'
require 'base64'