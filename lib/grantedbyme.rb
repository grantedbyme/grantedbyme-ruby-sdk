##
# The MIT License (MIT)
#
# Copyright (c) 2016 GrantedByMe
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

##
# GrantedByMe Ruby SDK
# author: GrantedByMe <info@grantedby.me>
#

class GrantedByMe

  VERSION = '1.0.9'
  BRANCH = 'master'
  HOST = 'https://api.grantedby.me/v1/service/'
  USER_AGENT = 'GrantedByMe/' + VERSION + '-' + BRANCH + ' (Ruby)'

  ##
  # Constructor
  #
  def initialize(private_key: nil, private_key_file: nil, server_key: nil, server_key_file: nil)
    @server_key = server_key
    @private_key = private_key
    # Load Service RSA private key
    if private_key_file and (File.file?(private_key_file))
      @private_key = open private_key_file, 'r' do |io|
        io.read
      end
    end
    # Load Server RSA public key
    if server_key_file and (File.file?(server_key_file))
      @server_key = open server_key_file, 'r' do |io|
        io.read
      end
    end
    @crypto = Crypto.new(@private_key, @server_key)
    @api_url = HOST
    @is_ssl_verify = true
    if @server_key
      @public_hash = Crypto.sha512(@server_key)
    end
  end

  ########################################
  # Getters / Setters
  ########################################

  ##
  # Returns the Service RSA public key in serialized PEM string format
  #
  def get_private_key
    @private_key
  end

  ##
  # Returns the Service RSA public key in serialized PEM string format
  #
  def get_public_key
    private_rsa = OpenSSL::PKey::RSA.new @private_key
    private_rsa.public_key.to_pem
  end

  ##
  # Returns the Server RSA public key in serialized PEM string format
  #
  def get_server_key
    @server_key
  end

  ##
  # Returns the crypto helper reference
  #
  def get_crypto
    @crypto
  end

  ##
  # Returns a random string with length
  #
  def get_random_string(length)
    Base64.strict_encode64(OpenSSL::Random.random_bytes(length))
  end

  ##
  # Switches SSL verify state (always enable in production)
  #
  def set_ssl_verify(is_enabled)
    @is_ssl_verify = is_enabled
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
        @public_hash = Crypto.sha512(@server_key)
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
    params['grantor'] = Crypto.sha512(grantor)
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
    params = get_params(client_ip, client_ua)
    params['token_type'] = type
    post(params, 'get_session_token')
  end

  ##
  # Retrieve a session link token state
  #
  def get_token_state(token, client_ip=nil, client_ua=nil)
    params = get_params(client_ip, client_ua)
    params['token'] = token
    post(params, 'get_session_state')
  end

  ##
  # Revokes an active session token
  #
  def revoke_session_token(token, client_ip=nil, client_ua=nil)
    params = get_params(client_ip, client_ua)
    params['token'] = token
    post(params, 'revoke_session_token')
  end

  ########################################
  # HELPERS
  ########################################

  ##
  # Assembles default POST request parameters
  #
  def get_params(client_ip=nil, client_ua=nil)
    params = {}
    params['timestamp'] = Time.now.to_i
    if client_ip
      params['remote_addr'] = client_ip
    end
    if client_ua
      params['http_user_agent'] = client_ua
    end
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
      if @is_ssl_verify
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      else
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end
    end
    encrypted_params = @crypto.encrypt(params)
    encrypted_params['public_hash'] = @public_hash
    request.body = encrypted_params.to_json
    response = http.request(request)
    result = JSON.parse(response.body)
    if result['payload']
      return @crypto.decrypt(result)
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