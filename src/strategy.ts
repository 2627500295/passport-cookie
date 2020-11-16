import passport from 'passport-strategy';
import { Request } from 'express';

import { Extract } from "./extract";
import { StrategyOptions, VerifiedCallback, VerifyCallback, VerifyCallbackWithRequest } from './interfaces';

/**
 * Creates an instance of `Strategy`.
 *
 * @class
 * @constructor
 *
 * @param [options] - 选项
 * @param [options.cookieName] - Cookie name (defaults: `"token"`)
 * @param [options.signed] - Are the cookie signed? (defaults: `false`)
 * @param [options.passReqToCallback] - when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * @param {Function} verify - 验证函数
 *
 * @example
 *
 * ```
 * const strategyOptions = {};
 *
 * function validate(token, done) {
 *   User.findByToken({ token }, (err, user) => {
 *     if (err) return done(err);
 *     if (!user) return done(null, false);
 *     return done(null, user);
 *   });
 * }
 *
 * const strategy = new Strategy(strategyOptions, validate);
 *
 * passport.use(strategy);
 * ```
 *
 * @public
 *
 */
export class Strategy extends passport.Strategy {
  /**
   * 名称
   */
  public name = 'cookie';

  /**
   * Cookie Name
   */
  private readonly cookieName: string;

  /**
   * 使用签名
   */
  private readonly signed: boolean;

  /**
   * 将 Request 传递给回调
   */
  private readonly passReqToCallback: boolean;

  /**
   * 验证函数
   */
  private readonly verify: any;

  /**
   * 构造函数
   *
   * @param options - 选项
   * @param verify - 验证函数
   *
   * @constructor
   * @public
   */
  // public constructor(verify?: Verify);
  // public constructor(options: StrategyOptions, verify?: Verify);
  // public constructor(options: Verify | StrategyOptions, verify?: Verify)
  public constructor(options: StrategyOptions, verify: VerifyCallback | VerifyCallbackWithRequest) {
    super();

    if (typeof options == 'function') {
      verify = options;
      options = {};
    }

    if (!verify) {
      throw new TypeError('CookieStrategy requires a verify callback');
    }

    this.cookieName = options.cookieName ?? 'token';
    this.signed = options.signed ?? false;
    this.passReqToCallback = options.passReqToCallback ?? false;
    this.verify = verify;
  }

  /**
   * 认证
   * @param request - 请求
   * @public
   */
  public authenticate(request: Request): void {
    const token: string | null = Extract.fromCookie(this.cookieName, this.signed)(request);

    if (!token) {
      return this.fail(new Error("No auth token"),401);
    }

    const verified: VerifiedCallback = (error: any, user?: any, info?: any) => {
      if (error) return this.error(error);
      if (!user) return this.fail(info, 401);
      return this.success(user, info);
    }

    try {
      if (this.passReqToCallback) return this.verify(request, token, verified);
      return this.verify(token, verified);
    } catch (error) {
      return this.error(error as Error);
    }
  }
}
