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