NoEdgeSoftware.Cryptography

No Edge Software
http://www.noedgesoftware.com/

This library provides wrappers around .NET encryption and hashing functions.

ALGORITHMS

  == Symmetric ==

  Symmetric_AES_CBC

    Standard AES algorithm, using AesCryptoServiceProvider. A key with size of 128 or 256
    bits is required. When encrypting, the first 16 bytes of the encrypted output is the IV,
    which is randomly generated with each new message. Overloads exist for encrypting byte arrays,
    strings, and streams.

    Usage:

    var key = Symmetric_AES.GenerateRandomKey(keySize);
    byte[] input = { 1, 2, 3, 4 };
    byte[] encrypted;
    using (var algorithm = new Symmetric_AES_CBC())
    {
        encrypted = algorithm.EncryptBytes(input, key);
    }

    using (var algorithm = new Symmetric_AES_CBC())
    {
        var decrypted = algorithm.DecryptBytes(encrypted, key);
    }

  Symmetric_AES_CBC_Passphrase

    The same as the Symmetric_AES_CBC class, except it accepts a string passphrase (no restrictions
    on passphrase length). The passphrase is converted into a key using PBKDF2 with a 16-byte salt,
    which is generated randomly. The first 16 bytes of the encrypted output are the IV, and the next 16 bytes
    are the salt.

  Symmetric_AES_ECB

    AES using ECB, using AesCryptoServiceProvider. No IV is used. A key size of 128 or 256
    bits is required. For a given input, the same output will always be generated. This should
    only be used in specific scenarios where this is a requirement. Overloads exist for encrypting
    byte arrays, strings, and streams.

    Usage:

    var key = Symmetric_AES.GenerateRandomKey(keySize);
    byte[] input = { 1, 2, 3, 4 };
    byte[] encrypted;
    using (var algorithm = new Symmetric_AES_ECB())
    {
        encrypted = algorithm.EncryptBytes(input, key);
    }

    using (var algorithm = new Symmetric_AES_ECB())
    {
        var decrypted = algorithm.DecryptBytes(encrypted, key);
    }

  Symmetric_AES_ECB_Passphrase

    The same as the Symmetric_AES_ECB class, except it accepts a string passphrase (no restrictions
    on passphrase length). The passphrase is converted into a key using PBKDF2 with a 16-byte salt,
    which is generated randomly. The first 16 bytes of the encrypted output are the salt.

  == Symmetric Authenticated ==

  SymmetricAuthenticated_AES_HMACSHA256

    AES CBC encryption using a 256-bit crypto key and 256-bit auth key. This produces an output consisting of
    a 16-byte IV, followed by the ciphertext, then ending with the 32-bytes of the HMACSHA256 tag of (IV+ciphertext).
    If the tag is incorrect, a CryptographicException will be thrown.

    Usage:

    byte[] cryptoKey, authKey;
    SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
    byte[] input = { 1, 2, 3, 4 };
    byte[] encrypted;
    using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
    {
        encrypted = algorithm.EncryptBytes(input, cryptoKey, authKey);
    }
    using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
    {
        var decrypted = algorithm.DecryptBytes(encrypted, cryptoKey, authKey);
    }

  == Asymmetric ==

  Asymmetric_RSA

    Standard RSA encryption, using RSACryptoServiceProvider. Generate a new key using
    Asymmetric_RSA.GenerateRandomPrivateKey. Key size must be between 384 and 16384 bits, in
    increments of 8 bits. The input to be encrypted must be less than ((keySize - 384) / 8) + 7 bytes.
    Overloads exist for encrypting byte arrays and strings. This library has only been tested on
    key sizes of 384, 1024, 2048, and 4096 bits.

    Usage:

    string privateXml, publicXml;
    Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
    byte[] input = { 1, 2, 3, 4 };
    byte[] encrypted;
    using (var algorithm = new Asymmetric_RSA())
    {
        encrypted = algorithm.EncryptBytes(input, publicXml);
    }
    using (var algorithm = new Asymmetric_RSA())
    {
        var decrypted = algorithm.DecryptBytes(encrypted, privateXml);
    }

  == Hash ==

  Hash_MD5
  Hash_RIPEMD160
  Hash_SHA1
  Hash_SHA256
  Hash_SHA384
  Hash_SHA512

    Wrappers around the standard .NET implementations.

    Usage:

    byte[] input = { 1, 2, 3, 4 };
    var algo = new Hash_MD5();
    byte[] result = algo.HashBytes(input);
    byte[] result2 = algo.HashString("Some text");
    using (var inputStream = new MemoryStream(new byte[] { 1, 2, 3, 4 }))
    {
        byte[] result3 = algo.HashStream(inputStream);
    }

  == Password generation ==

  PBKDF2

    Wrapper around Rfc2898DeriveBytes, used to generate hashed, salted values for passwords,
    or for converting passphrases into secret keys for encryption. Default number of iterations
    is 0x4000, and the default number of bytes for both hashed password and salt is 32.

    Usage:

    // If you are creating the hash from a new password:
    byte[] salt;
    byte[] hashedPassword = PBKDF2.ComputeHash("mypassword", out salt);

    // If you already have the salt, and are computing the hash for comparison:
    byte[] salt = mySalt;
    byte[] hashedPassword = PBKDF2.ComputeHash("mypassword", salt);

RESULTS

  EncryptionResults
  HashResults

    A wrapper around a byte array, with methods to convert to hex, base64, or ASCII-85.

    Usage:

    byte[] input = { 1, 2, 3, 4 };
    var algo = new Hash_MD5();
    string base64Result = algo.HashBytes(input).AsBase64();

  DecryptionResults

    A wrapper around a byte array, with methods to convert to hex, base64, ASCII-85, or
    a string (if the original input was a string).

    Usage:

    var key = Symmetric_AES.GenerateRandomKey(keySize);
    string input = "Hello!";
    byte[] encrypted;
    using (var algorithm = new Symmetric_AES_CBC())
    {
        encrypted = algorithm.EncryptString(input, key);
    }

    using (var algorithm = new Symmetric_AES_CBC())
    {
        string decrypted = algorithm.DecryptBytes(encrypted, key).AsString();
    }

RANDOMIZER

  SecureRandomizer

    This is a wrapper around System.Security.Cryptography.RandomNumberGenerator.Create.
    A random buffer is generated in advance, and bytes retrieved from the buffer, saving
    the overhead of building a random array every time on demand.

    Usage:

    byte[] randomBytes = SecureRandomizer.GetRandomBytes(32);

CONVERTERS

  Ascii85Converter

    Wrapper around Jeff Atwood's Ascii85 class found at http://www.codinghorror.com/blog/archives/000410.html

    Usage:

    byte[] input = { 1, 2, 3, 4 };
    string ascii85 = Ascii85Converter.BytesToAscii85(input);
    byte[] output = Ascii85Converter.Ascii85ToBytes(ascii85);

  HexConverter

    Methods to convert to/from hex/bytes, with options for upper/lower case, and an optional delimiter.

    Usage:

    byte[] input = { 1, 2, 3, 4 };
    string hexUpperNoDelimiter = HexConverter.BytesToHex(input);
    string hexUpperDelimiter = HexConverter.BytesToHex(input, '-');
    string hexLowerNoDelimter = HexConverter.BytesToHex(input, upperCase: false);
    string hexLowerDelimiter = HexConverter.BytesToHex(input, '|', false);

    byte[] output = HexConverter.HexToBytes(hexUpperNoDelimiter); // will accept any of these forms
