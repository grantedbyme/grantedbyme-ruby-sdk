##
# GrantedByMe Ruby SDK - RSA Crypto Helper
# author: GrantedByMe <info@grantedby.me>
#

class RSA

  ##
  # Constructor
  #
  def initialize(private_key, public_key)
    if private_key && public_key
      load_keypair(private_key, public_key)
    end
  end

  ##
  # Returns the RSA private key in serialized PEM format
  #
  def get_private_key
    return @private_key
  end

  ##
  # Returns the RSA public key in serialized PEM format
  #
  def get_public_key
    return @public_key
  end

  ##
  # Generates a new RSA key pair
  #
  def generate_keypair
    key = OpenSSL::PKey::RSA.new 2048
    load_keypair(key.to_pem, key.public_key.to_pem)
    return [@private_key, @public_key]
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

  ##
  # Encrypts a String using RSA encryption
  #
  def encrypt(data)
    return @public_rsa.public_encrypt(data, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  end

  ##
  # Decrypts a String using RSA encryption
  #
  def decrypt(data)
    return @private_rsa.private_decrypt(data, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  end

  ##
  # Signs an input using RSA SHA-512
  #
  def sign(data)
    return @private_rsa.sign(OpenSSL::Digest::SHA512.new, data)
  end

  ##
  # Verifies a RSA signature
  #
  def verify(signature, data)
    return @public_rsa.verify(OpenSSL::Digest::SHA512.new, signature, data)
  end

end

require 'openssl'
require 'digest/sha2'