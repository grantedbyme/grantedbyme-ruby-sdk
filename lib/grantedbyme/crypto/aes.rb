##
# GrantedByMe Ruby SDK - AES Crypto Helper
# author: GrantedByMe <info@grantedby.me>
#

class AES

  ##
  # Constructor
  #
  def initialize()
    @alg = 'AES-256-CBC'
  end

  ##
  # Encrypts an input String using AES
  #
  def encrypt(data)
    aes = OpenSSL::Cipher::Cipher.new(@alg)
    aes.encrypt()
    key = aes.random_key()
    iv = aes.random_iv()
    signature = sign(data, key)
    result = aes.update(data)
    result << aes.final
    return [result, key, iv, signature]
  end

  ##
  # Decrypts an input String using AES
  #
  def decrypt(data, key, iv)
    cipher = OpenSSL::Cipher::Cipher.new(@alg)
    cipher.decrypt()
    cipher.key = key
    cipher.iv = iv
    result = cipher.update(data)
    result << cipher.final
    return result
  end

  ##
  # Signs an input String using HMAC-SHA-256
  #
  def sign(data, key)
    return OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, data)
  end

  ##
  # Verifies a String using HMAC-SHA-256
  #
  def verify(data, key, signature)
    new_signature = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), key, data)
    return signature == new_signature
  end

end

require 'openssl'
require 'digest/sha2'