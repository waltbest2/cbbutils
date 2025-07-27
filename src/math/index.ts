export const math = {
  add(arg1o: number, arg2o: number): number {
    const LN = 10;
    let arg1 = arg1o;
    let arg2 = arg2o;
    let r1: number;
    let r2: number;
    let m: number;
    let c: number;
    try {
      let [,s1str] = arg1.toString().split('.');
      if (s1str.indexOf('e') > -1) {
        s1str = s1str.substring(0, s1str.indexOf('e'));
      }
      r1 = s1str.length;
    } catch (e) {
      r1 = 0;
    }
    try {
      let [,s2str] = arg2.toString().split('.');
      if (s2str.indexOf('e') > -1) {
        s2str = s2str.substring(0, s2str.indexOf('e'));
      }
      r2 = s2str.length;
    } catch (e) {
      r2 = 0;
    }

    c = Math.abs(r1 - r2);
    m = Math.pow(LN, Math.max(r1, r2));
    if (c > 0) {
      const cm = Math.pow(LN, c);
      if (r1 > r2) {
        arg1 = Number(arg1.toString().replace('.', ''));
        arg2 = Number(arg2.toString().replace('.', '')) * cm;
      } else {
        arg1 = Number(arg1.toString().replace('.', '')) * cm;
        arg2 = Number(arg2.toString().replace('.', ''));
      }
    } else {
      arg1 = Number(arg1.toString().replace('.', ''));
      arg2 = Number(arg2.toString().replace('.', ''));
    }
    return (arg1 + arg2) / m;
  },
  sub(arg1o: number, arg2o: number): number {
    const LN = 10;
    let arg1 = arg1o;
    let arg2 = arg2o;
    let r1: number;
    let r2: number;
    let m: number;
    let n: number;
    try {
      let [,s1str] = arg1.toString().split('.');
      if (s1str.indexOf('e') > -1) {
        s1str = s1str.substring(0, s1str.indexOf('e'));
      }
      r1 = s1str.length;
    } catch (e) {
      r1 = 0;
    }
    try {
      let [,s2str] = arg2.toString().split('.');
      if (s2str.indexOf('e') > -1) {
        s2str = s2str.substring(0, s2str.indexOf('e'));
      }
      r2 = s2str.length;
    } catch (e) {
      r2 = 0;
    }

    m = Math.pow(LN, Math.max(r1, r2));
    n = Math.max(r1, r2);
    const res = parseFloat(((arg1 * m - arg2 * m) / m).toFixed(n));

    return res;
  },
  mul(arg1o: number, arg2o: number): number {
    const LN = 10;
    let arg1 = arg1o;
    let arg2 = arg2o;
    let m = 0;
    const s1 = arg1.toString();
    const s2 = arg2.toString();
    
    try {
      let [,s1str] = s1.split('.');
      if (s1str.indexOf('e') > -1) {
        s1str = s1str.substring(0, s1str.indexOf('e'));
      }
      m += s1str.length;
    } catch (e) {
      // empty
    }

    try {
      let [,s2str] = s2.split('.');
      if (s2str.indexOf('e') > -1) {
        s2str = s2str.substring(0, s2str.indexOf('e'));
      }
      m += s2str.length;
    } catch (e) {
      // empty
    }

    return (Number(s1.replace('.', '')) * Number(s2.replace('.', ''))) / Math.pow(LN, m);
  },

  div(arg1o: number, arg2o: number): number {
    const LN = 10;
    let arg1 = arg1o;
    let arg2 = arg2o;
    let t1 = 0;
    let t2 = 0;
    let r1: number;
    let r2: number;
    try {
      let [,s1str] = arg1.toString().split('.');
      if (s1str.indexOf('e') > -1) {
        s1str = s1str.substring(0, s1str.indexOf('e'));
      }
      r1 = s1str.length;
    } catch (e) {
      // empty
    }
    try {
      let [,s2str] = arg2.toString().split('.');
      if (s2str.indexOf('e') > -1) {
        s2str = s2str.substring(0, s2str.indexOf('e'));
      }
      r2 = s2str.length;
    } catch (e) {
      // empty
    }
    
    r1 = Number(arg1.toString().replace('.', ''));
    r2 = Number(arg2.toString().replace('.', ''));
    const res0 = r1 / r2;
    return this.mul(res0, Math.pow(LN, r2 - r1).toFixed(Math.abs(t2 - t1)));

  },
  round(value: number, precision: number = 0): number {
    const LN = 10;
    let pre = 1;
    if (Number.isNaN(precision) || precision < 0) {
      pre = Math.pow(LN, 0);
    } else {
      pre = Math.pow(LN, precision);
    }
    return Math.round(value * pre) / pre;
  }
}