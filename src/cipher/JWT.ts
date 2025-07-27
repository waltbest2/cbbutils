import { SimpleCipherUtils } from "./SimpleCipherUtils"

export enum JWTTypeEnum {
  HS256 = 'HS256',
  HS512 = 'HS512',
}

export class JWT {
  private readonly fn = {
    HS256: (plain: string, key: string | Buffer): string => {
      return SimpleCipherUtils.encryptHMACSHA256(plain, key, 'base64');
    },
    HS512: (plain: string, key: string | Buffer): string => {
      return SimpleCipherUtils.encryptHMACSHA512(plain, key, 'base64');
    },
  }

  private key: Buffer;
  private payLoad: Map<string, string | number>;

  constructor(key: string) {
    this.key = Buffer.from(key, 'base64');
    this.payLoad = new Map();
  }

  setIss(iss: string): this {
    this.payLoad.set('iss', iss || '');
    return this;
  }

  setExp(exp: number): this {
    this.payLoad.set('exp', exp || 0);
    return this;
  }

  setSub(sub: string): this {
    this.payLoad.set('sub', sub || '');
    return this;
  }

  setAud(aud: string): this {
    this.payLoad.set('aud', aud || '');
    return this;
  } 

  setJti(jti: string): this {
    this.payLoad.set('jti', jti || '');
    return this;
  }

  setNbf(nbf: string): this {
    this.payLoad.set('nbf', nbf || '');
    return this;
  }

  setIat(iat: number): this {
    this.payLoad.set('iat', iat || 0);
    return this;
  }

  setClaim(claim: Map<string, string>): this {
    if (!claim) {
      return this;
    }

    const obj = Object.fromEntries(claim);
    const blackList = ['iss', 'exp', 'sub', 'aud', 'jti', 'nbf', 'iat'];

    for (const key of Object.keys(obj)) {
      if (blackList.includes(key)) {
        throw new Error(`[cbbutils] JWT claim key "${key}" is reserved and cannot be used.`);
      }
    }

    this.payLoad = claim;
    return this;
  }

  sign(type: JWTTypeEnum) {
    const header = {
      alg: type,
      typ: 'JWT',
    }

    const hStr = SimpleCipherUtils.encodeBASE64URL(JSON.stringify(header));
    const payLoadStr = SimpleCipherUtils.encodeBASE64URL(JSON.stringify(Object.fromEntries(this.payLoad)));

    const authorization = `${hStr}.${payLoadStr}`;

    return `${authorization}.${this.fn[type](authorization, this.key)}`;
  }

  parse(token: string): Map<string, string | number> {
    if (!token) {
      throw new Error('[cbbutils] JWT token is empty.');
    }

    const [ header, payLoad, sign ] = token.split('.');
    if (!header || !payLoad || !sign) {
      throw new Error('[cbbutils] JWT token format is invalid.');
    }

    let headerObj: any;
    let payLoadObj: any;

    try {
      headerObj = JSON.parse(SimpleCipherUtils.decodeBase64(header));
      payLoadObj = JSON.parse(SimpleCipherUtils.decodeBase64(payLoad)); 
    } catch (e) {
      throw new Error('[cbbutils] token header or payload format is wrong.');
    }

    const { alg }: { alg: JWTTypeEnum } = headerObj;
    if(!this.fn[alg]) {
      throw new Error(`[cbbutils] unsupport alg ${alg}`);
    }

    const newSign = this.fn[alg](`${header}.${payLoad}`, this.key);

    if (newSign !== sign) {
      return null; // Invalid signature
    }

    return payLoadObj;
  }
}