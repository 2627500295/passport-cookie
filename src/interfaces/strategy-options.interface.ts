export interface StrategyOptions {
  /**
   * Cookie Name
   */
  cookieName?: string;

  /**
   * 使用签名
   */
  signed?: boolean;

  /**
   * 将 Request 传递给回调
   */
  passReqToCallback?: boolean;
}
