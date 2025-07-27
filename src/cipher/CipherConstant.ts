export class CipherConstant {
  public static readonly CHAR_SET_UTF8 = 'utf8';
  public static readonly HEX_ENCODING = 'hex';
  public static readonly CRIPT_GCM = 'aes-256-gcm';
  public static readonly CRIPT_CBC = 'aes-256-cbc';
  public static readonly CRIPT_128CBC = 'aes-128-cbc';
  public static readonly PBKDF2_LENGTH = 32; // Length of the derived key
  public static readonly PBKDF2_DIGEST = 'sha1';
  public static readonly PBKDF2_ITERATIONS = 50000; // Number of iterations for key derivation
  public static readonly DECRIPT_CBC = 'aes256';

  /**
   * 工作密钥
   */
  public static readonly WORKKEY_NAME = 'common.key';

  /**
   * 根密钥
   */
  public static readonly ROOTKEY_NAME = 'root.key';
  public static readonly SM4_CBC = 'cbc';
  public static readonly CRIPT_SHA256 = 'sha256';
  public static readonly CRIPT_SHA512 = 'sha512';
  public static readonly CRIPT_BASE64 = 'base64';
  public static readonly CRIPT_BASE64URL = 'base64url';
  public static readonly CRIPT_MD5 = 'md5';
  public static readonly IV_LENGTH = 32;
  public static readonly HALF_IV_LENGTH = 16; // Half of the IV length for certain operations
}