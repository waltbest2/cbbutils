import { sm4 } from "sm-crypto";
import { BaseCipher } from "./BaseCipher";
import { CipherConstant } from "./CipherConstant";

export class GMCipherUtils extends BaseCipher {
  constructor(keyPath?: string) {
    super(keyPath, CipherConstant.HALF_IV_LENGTH);
  }

  public encryptSM4(plain: string): string {
    return this.encryptByKey(plain, this.cryptKey);
  }

  public decryptSM4(encrypted: string): string {
    if (!encrypted) {
      return '';
    }
    return this.decryptByKey(encrypted, this.cryptKey);
  }

  protected encryptByKey(plain: string, key: Buffer): string {
    const iv = this.generateIV().toString(CipherConstant.HEX_ENCODING);
    const encryptContent = sm4.encrypt(plain, key, { mode: CipherConstant.SM4_CBC, iv: iv });
    return this.getFinalEncryptContent(iv, encryptContent);
  }

  protected decryptByKey(encrypted: string, key: Buffer): string {
    const { content: encryptContent, iv } = this.getContentPair(encrypted);
   
    return sm4.decrypt(encryptContent, key, { mode: CipherConstant.SM4_CBC, iv: iv });
  }
}