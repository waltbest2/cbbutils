import { create } from "domain";
import { BaseCipher } from "./BaseCipher";
import { CipherConstant } from "./CipherConstant";
import { Cipher, createCipheriv, createDecipheriv, Decipher } from "crypto";

export class CipherUtils extends BaseCipher{
  
  constructor(keyPath?: string) {
    super(keyPath, CipherConstant.IV_LENGTH);
  }

  public encryptAES(plain: string): string {
    return this.encryptByKey(plain, this.cryptKey);
  }

  public decryptAES(encrypted: string): string {
    if (!encrypted) {
      return '';
    }
    return this.decryptByKey(encrypted, this.cryptKey);
  }

  protected encryptByKey(plain: string, key: Buffer): string {
    const iv = this.generateIV();
    const cipheriv: Cipher = createCipheriv(CipherConstant.CRIPT_GCM, key, iv);
    let encryptContent: string = cipheriv.update(plain, CipherConstant.CHAR_SET_UTF8, CipherConstant.HEX_ENCODING);
    encryptContent += cipheriv.final(CipherConstant.HEX_ENCODING);
    return this.getFinalEncryptContent(iv.toString(CipherConstant.HEX_ENCODING), encryptContent); 
  }

  protected decryptByKey(encrypted: string, key: Buffer): string {
    const { content: encryptContent, iv: ivs } = this.getContentPair(encrypted);
    const iv = Buffer.from(ivs, CipherConstant.HEX_ENCODING);
    const decipheriv: Decipher = createDecipheriv(CipherConstant.CRIPT_GCM, key, iv);
    
    return decipheriv.update(encryptContent, CipherConstant.HEX_ENCODING, CipherConstant.CHAR_SET_UTF8);
  }
}