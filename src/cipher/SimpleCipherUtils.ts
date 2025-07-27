import { BinaryToTextEncoding, createHash, createHmac, Hash, Hmac } from "crypto";
import { CipherConstant } from "./CipherConstant";

export class SimpleCipherUtils {

  static encryptMD5(plain: string): string {
    const hash: Hash = createHash(CipherConstant.CRIPT_MD5);
    return hash.update(plain, CipherConstant.CHAR_SET_UTF8).digest(CipherConstant.HEX_ENCODING);
  }

  static encodeBase64(plain: string): string {
    return Buffer.from(plain).toString(CipherConstant.CRIPT_BASE64);
  }

  static encodeBASE64URL(plain: string): string {
    return Buffer.from(plain).toString(CipherConstant.CRIPT_BASE64URL);
  }

  static decodeBase64(encoded: string): string {
    return Buffer.from(encoded, CipherConstant.CRIPT_BASE64).toString(CipherConstant.CHAR_SET_UTF8);
  }

  static encryptSHA256(plain: string | Buffer): string {
    const hash: Hash = createHash(CipherConstant.CRIPT_SHA256);
    return hash.update(plain as any, CipherConstant.CHAR_SET_UTF8).digest(CipherConstant.HEX_ENCODING);
  }

  static encryptHMACSHA256(plain: string, key: string | Buffer, type: BinaryToTextEncoding = 'base64'): string {
    const hash: Hmac = createHmac(CipherConstant.CRIPT_SHA256, key);
    return hash.update(plain, CipherConstant.CHAR_SET_UTF8).digest(type);
  }

  static encryptHMACSHA512(plain: string, key: string | Buffer, type: BinaryToTextEncoding = 'base64'): string {
    const hash: Hmac = createHmac(CipherConstant.CRIPT_SHA512, key);
    return hash.update(plain, CipherConstant.CHAR_SET_UTF8).digest(type);
  }
}