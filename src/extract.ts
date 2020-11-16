import {Request} from "express";

export class Extract {
  public static fromCookie(name: string, signed: boolean = false) {
    return function (request: Request): string | null {
      const cookies = request[signed ? 'signedCookies' : 'cookies'];
      if (!cookies) {
        throw new TypeError('Maybe you forgot to use cookie-parser?');
      }
      return cookies?.[name] ?? null;
    }
  }
}
