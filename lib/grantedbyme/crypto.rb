##
# GrantedByMe Ruby SDK
# author: GrantedByMe <info@grantedby.me>
#

class Crypto

  ##
  # Constructor
  #
  def initialize()
  end

  ########################################
  # API
  ########################################

  ##
  # Encrypts a Hash using compound encryption
  #
  def encrypt(data, private_key, public_key)
    aes = AES.new()
    rsa = RSA.new(private_key, public_key)
    plain_text = data.to_json
    if plain_text.length < 255
      rsa_result = rsa.encrypt(plain_text)
      rsa_signature = rsa.sign(plain_text)
      result = {payload: Base64.strict_encode64(rsa_result), signature: Base64.strict_encode64(rsa_signature), alg: 'RS512'}
    else
      aes_result = aes.encrypt(plain_text)
      message = Base64.strict_encode64(aes_result[0])
      aes_key = Base64.strict_encode64(aes_result[1])
      aes_iv = Base64.strict_encode64(aes_result[2])
      aes_signature = Base64.strict_encode64(aes_result[3])
      rsa_data = {
          cipher_key: aes_key,
          cipher_iv: aes_iv,
          signature: aes_signature,
          timestamp: Time.now.to_i
      }
      rsa_result = rsa.encrypt(rsa_data.to_json)
      rsa_signature = rsa.sign(rsa_data.to_json)
      result = {payload: Base64.strict_encode64(rsa_result), signature: Base64.strict_encode64(rsa_signature), message: message, alg: 'RS512'}
    end
    return result
  end

  ##
  # Decrypts a Hash using compound encryption
  #
  def decrypt(data, private_key, public_key)
    aes = AES.new()
    rsa = RSA.new(private_key, public_key)
    payload = Base64.strict_decode64(data['payload'])
    signature = Base64.strict_decode64(data['signature'])
    cipher_data = rsa.decrypt(payload)
    cipher_json = JSON.parse(cipher_data)
    if (!rsa.verify(signature, cipher_data))
      raise 'Invalid RSA signature'
    end
    if !data.has_key?('message') and !cipher_json.has_key?('cipher_key') and !cipher_json.has_key?('cipher_iv') and !cipher_json.has_key?('signature')
      return cipher_json
    else
      cipher_key = Base64.strict_decode64(cipher_json['cipher_key'])
      cipher_iv = Base64.strict_decode64(cipher_json['cipher_iv'])
      cipher_signature = Base64.strict_decode64(cipher_json['signature'])
      message = Base64.strict_decode64(data['message'])
      result = aes.decrypt(message, cipher_key, cipher_iv)
      if !aes.verify(result, cipher_key, cipher_signature)
        raise 'Invalid HMAC signature'
      end
      return JSON.parse(result)
    end
  end

  ########################################
  # STATIC METHODS
  ########################################

  ##
  # Calculates SHA-512 digest for an input String
  #
  def self.digest(input_string)
    normalized_string = input_string.encode(input_string.encoding, :universal_newline => true)
    return Digest::SHA2.new(512).hexdigest(normalized_string)
  end

end

require 'grantedbyme/crypto/aes'
require 'grantedbyme/crypto/rsa'
require 'json'
require 'base64'