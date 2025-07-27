import fs from "fs";
import path from "path";
import { Buffer } from "buffer";
import { scryptSync } from "crypto";
import { CipherConstant } from "./CipherConstant";
import { nanoid } from "nanoid";

export abstract class BaseCipher {
  protected cryptKey: Buffer;

  protected keyLength: number;

  private keyPath = `${process.env.sshhome || '/opt/service'}/config/key`;

  constructor(keyPath?: string, keyLength = CipherConstant.IV_LENGTH) {
    if (keyPath) {
      this.keyPath = keyPath;
    }

    if (!fs.existsSync(this.keyPath)) {
      fs.mkdirSync(this.keyPath, { recursive: true, mode: 0o600 });
    }
    this.keyLength = keyLength;
    this.cryptKey = this.readWorkKey();
  }

  protected abstract encryptByKey(plain: string, key: Buffer): string;
  protected abstract decryptByKey(encrypted: string, key: Buffer): string;

  private readWorkKey(): Buffer {
    const workKeyPath = path.join(this.keyPath, CipherConstant.WORKKEY_NAME);

    const rootKeyPath = path.join(this.keyPath, CipherConstant.ROOTKEY_NAME);

    let rootKey: Buffer;
    if (fs.existsSync(rootKeyPath)) {
      rootKey = fs.readFileSync(rootKeyPath);
    } else {
      rootKey = this.generateRootKey(rootKeyPath);
    }

    let workKey: Buffer;
    if (fs.existsSync(workKeyPath)) {
      return fs.readFileSync(workKeyPath);
    } else {
      workKey = this.generateWorkKey(workKeyPath, rootKey);
    }

    const workKeystr = this.decryptByKey(workKey.toString(CipherConstant.HEX_ENCODING), rootKey);

    return Buffer.from(workKeystr, CipherConstant.HEX_ENCODING);
  }

  protected generateIV(): Buffer {
    return Buffer.from(this.genIv(), CipherConstant.CHAR_SET_UTF8);
  }

  protected generateRootKey(keyPath: string): Buffer {
    const oirgK = nanoid(this.keyLength);
    const salt = this.genIv();
    const rootKey = scryptSync(oirgK, salt, this.keyLength);
    fs.writeFileSync(keyPath, rootKey, { mode: 0o400 });
    return rootKey;
  }

  protected generateWorkKey(keyPath: string, rootKey: Buffer): Buffer {
    const oirgK = nanoid(this.keyLength);
    const salt = this.genIv();
    const workKey = scryptSync(oirgK, salt, this.keyLength);
    const encryptedWorkKey = this.encryptByKey(workKey.toString(CipherConstant.HEX_ENCODING), rootKey);
    fs.writeFileSync(keyPath, Buffer.from(encryptedWorkKey, CipherConstant.HEX_ENCODING), { mode: 0o400 });
    return workKey;
  }

  protected getContentPair(decriptContent: string): { content: string; iv: string } {
    return {
      content: decriptContent.substring(CipherConstant.IV_LENGTH),
      iv: decriptContent.substring(0, CipherConstant.IV_LENGTH),
    };
  }

  protected getFinalEncryptContent(iv: string, content: string): string {
    return iv + content;
  }

  private genIv(): string {
    return nanoid(CipherConstant.HALF_IV_LENGTH);
  }

}