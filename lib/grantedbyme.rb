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

  VERSION = '1.0.12'
  BRANCH = 'master'
  HOST = 'https://api.grantedby.me/v1/service/'
  USER_AGENT = 'GrantedByMe/' + VERSION + '-' + BRANCH + ' (Ruby)'

  CHALLENGE_AUTHORIZE = 1
  CHALLENGE_AUTHENTICATE = 2
  CHALLENGE_PROFILE = 4

  def self.challenge_authorize
    CHALLENGE_AUTHORIZE
  end

  def self.challenge_authenticate
    CHALLENGE_AUTHENTICATE
  end

  def self.challenge_profile
    CHALLENGE_PROFILE
  end

  ##
  # Creates a new GrantedByMe SDK instance.
  #
  # ==== Attributes
  #
  # * +private_key+ - Service RSA private key encoded in PEM format
  # * +private_key_file+ - The path to the service RSA private key
  # * +server_key+ - Server RSA public key encoded in PEM format
  # * +server_key_file+ - The path to the server RSA public key
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
  # Switches SSL verify state (always enable in production)
  #
  def set_ssl_verify(is_enabled)
    @is_ssl_verify = is_enabled
  end

  ########################################
  # API
  ########################################

  ##
  # Initiate key exchange for encrypted communication.
  #
  # ==== Attributes
  #
  # * +public_key+ - Service RSA public key encoded in PEM format
  #
  def activate_handshake(public_key)
    params = get_params
    params['public_key'] = public_key
    post(params, 'activate_handshake')
  end

  ##
  # Active pending service using service key.
  #
  # ==== Attributes
  #
  # * +service_key+ - The activation service key
  #
  def activate_service(service_key)
    key = OpenSSL::PKey::RSA.new 2048
    @private_key = key.to_pem
    handshake = activate_handshake(key.public_key.to_pem)
    if handshake && handshake['success'] && handshake['public_key']
      @server_key = handshake['public_key']
      @public_hash = Crypto.sha512(@server_key)
    else
      raise 'Handshake failed'
    end
    params = get_params
    params['service_key'] = service_key
    post(params, 'activate_service')
  end

  ##
  # Deactivate service for reactivation.
  #
  def deactivate_service
    params = get_params
    post(params, 'deactivate_service')
  end

  ##
  # Links a service user account with a GrantedByMe account.
  #
  # ==== Attributes
  #
  # * +challenge+ - The challenge used to verify the user
  # * +authenticator_secret+ - The secret used for user authentication
  #
  def link_account(challenge, authenticator_secret)
    params = get_params
    params['challenge'] = challenge
    params['authenticator_secret'] = authenticator_secret
    post(params, 'link_account')
  end

  ##
  # Un-links a service user account with a GrantedByMe account.
  #
  # ==== Attributes
  #
  # * +authenticator_secret+ - The secret used for user authentication
  #
  def unlink_account(authenticator_secret)
    params = get_params
    params['authenticator_secret'] = authenticator_secret
    post(params, 'unlink_account')
  end

  ##
  # Returns a challenge with required type.
  #
  # ==== Attributes
  #
  # * +challenge_type+ - The type of requested challenge
  # * +client_ip+ - The client IP address
  # * +client_ua+ - The client user-agent identifier
  #
  def get_challenge(challenge_type, client_ip=nil, client_ua=nil)
    params = get_params(client_ip, client_ua)
    params['challenge_type'] = challenge_type
    post(params, 'get_challenge')
  end

  ##
  # Returns a challenge state.
  #
  # ==== Attributes
  #
  # * +challenge+ - The challenge to check
  # * +client_ip+ - The client IP address
  # * +client_ua+ - The client user-agent identifier
  #
  def get_challenge_state(challenge, client_ip=nil, client_ua=nil)
    params = get_params(client_ip, client_ua)
    params['challenge'] = challenge
    post(params, 'get_challenge_state')
  end

  ##
  # Notify the GrantedByMe server about the user has been logged out from the service.
  #
  # ==== Attributes
  #
  # * +challenge+ - The challenge representing an active authentication session
  #
  def revoke_challenge(challenge)
    params = get_params
    params['challenge'] = challenge
    post(params, 'revoke_challenge')
  end

  ########################################
  # HELPERS
  ########################################

  ##
  # Returns the default HTTP parameters
  #
  # ==== Attributes
  #
  # * +client_ip+ - The client IP address
  # * +client_ua+ - The client user-agent identifier
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
  # Sends a HTTP (POST) API request
  #
  # ==== Attributes
  #
  # * +params+ - The request parameter object
  # * +operation+ - The API operation name
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
    if operation == 'activate_handshake'
      encrypted_params = params
    else
      encrypted_params = @crypto.encrypt(params)
      encrypted_params['public_hash'] = @public_hash
    end
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

  ########################################
  # STATIC
  ########################################

  ##
  # Generates a secure random authenticator secret.
  #
  def self.generate_authenticator_secret
    Crypto.random_string(128)
  end

  ##
  # Generates hash digest of an authenticator secret.
  #
  # ==== Attributes
  #
  # * +authenticator_secret+ - The authenticator secret to hash
  #
  def self.hash_authenticator_secret(authenticator_secret)
    Crypto.sha512(authenticator_secret)
  end

end

require 'date'
require 'json'
require 'net/http'
require 'grantedbyme/crypto'
require 'openssl'
require 'base64'