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

class Crypto

  ##
  # Constructor
  #
  def initialize(private_key = nil, public_key = nil)
    if private_key && public_key
      load_keypair(private_key, public_key)
    end
  end

  ##
  # Returns the RSA private key in serialized PEM format
  #
  def get_private_key
    @private_key
  end

  ##
  # Returns the RSA public key in serialized PEM format
  #
  def get_public_key
    @public_key
  end

  ##
  # Generates a new RSA key pair
  #
  def generate_keypair
    key = OpenSSL::PKey::RSA.new 2048
    load_keypair(key.to_pem, key.public_key.to_pem)
    [@private_key, @public_key]
  end

  ##
  # Loads an RSA key pair from PEM strings
  #
  def load_keypair(private_key, public_key)
    @private_key = private_key
    @public_key = public_key
    @private_rsa = OpenSSL::PKey::RSA.new @private_key
    @public_rsa = OpenSSL::PKey::RSA.new @public_key
  end

  ########################################
  # API
  ########################################

  ##
  # Encrypts a Hash using compound encryption
  #
  def encrypt(data)
    plain_text = data.to_json
    if plain_text.length < 215
      rsa_result = @public_rsa.public_encrypt(plain_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      rsa_signature = @private_rsa.sign(OpenSSL::Digest::SHA512.new, plain_text)
      result = {
          payload: Base64.strict_encode64(rsa_result),
          signature: Base64.strict_encode64(rsa_signature),
          alg: 'RS512'
      }
    else
      aes = OpenSSL::Cipher::Cipher.new('AES-256-CBC')
      aes.encrypt
      key = aes.random_key
      iv = aes.random_iv
      aes_signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, plain_text)
      aes_result = aes.update(plain_text)
      aes_result << aes.final
      rsa_data = {
          cipher_key: Base64.strict_encode64(key),
          cipher_iv: Base64.strict_encode64(iv),
          signature: Base64.strict_encode64(aes_signature),
          timestamp: Time.now.to_i
      }
      rsa_result = @public_rsa.public_encrypt(rsa_data.to_json, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      rsa_signature = @private_rsa.sign(OpenSSL::Digest::SHA512.new, rsa_data.to_json)
      result = {
          payload: Base64.strict_encode64(rsa_result),
          signature: Base64.strict_encode64(rsa_signature),
          message: Base64.strict_encode64(aes_result),
          alg: 'RS512'
      }
    end
    result
  end

  ##
  # Decrypts a Hash using compound encryption
  #
  def decrypt(data)
    payload = Base64.strict_decode64(data['payload'])
    signature = Base64.strict_decode64(data['signature'])
    cipher_data = @private_rsa.private_decrypt(payload, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    cipher_json = JSON.parse(cipher_data)
    if !@public_rsa.verify(OpenSSL::Digest::SHA512.new, signature, cipher_data)
      raise 'Invalid RSA signature'
    end
    if !data.has_key?('message') and !cipher_json.has_key?('cipher_key') and !cipher_json.has_key?('cipher_iv') and !cipher_json.has_key?('signature')
      cipher_json
    else
      cipher_key = Base64.strict_decode64(cipher_json['cipher_key'])
      cipher_iv = Base64.strict_decode64(cipher_json['cipher_iv'])
      cipher_signature = Base64.strict_decode64(cipher_json['signature'])
      message = Base64.strict_decode64(data['message'])
      cipher = OpenSSL::Cipher::Cipher.new('AES-256-CBC')
      cipher.decrypt
      cipher.key = cipher_key
      cipher.iv = cipher_iv
      result = cipher.update(message)
      result << cipher.final
      if cipher_signature != OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), cipher_key, result)
        raise 'Invalid HMAC signature'
      end
      JSON.parse(result)
    end
  end

  ########################################
  # STATIC METHODS
  ########################################

  ##
  # Calculates SHA-512 digest for an input String
  #
  def self.sha512(data)
    normalized_string = data.encode(data.encoding, :universal_newline => true)
    return Digest::SHA2.new(512).hexdigest(normalized_string)
  end

  ##
  # Generates a password hash of input data
  #
  def self.pbkdf2(data, salt)
    # salt = OpenSSL::Random.random_bytes(16)
    digest = OpenSSL::Digest::SHA256.new
    OpenSSL::PKCS5.pbkdf2_hmac(data, salt, 100000, digest.digest_length, digest)
  end

  ##
  # Returns a random string with length
  #
  def self.random_string(length)
    Base64.strict_encode64(OpenSSL::Random.random_bytes(length))
  end

  ##
  # Safe equal time comparison helper
  #
  def eql_time_cmp(a, b)
    unless a.length == b.length
      return false
    end
    cmp = b.bytes.to_a
    result = 0
    a.bytes.each_with_index {|c,i|
      result |= c ^ cmp[i]
    }
    result == 0
  end

end

require 'json'
require 'base64'
require 'openssl'
require 'digest/sha2'