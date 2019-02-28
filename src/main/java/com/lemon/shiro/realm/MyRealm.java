package com.lemon.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

/**
 * @author YZH
 * @date 2019/2/28 16:49
 */
public class MyRealm implements Realm {

    /**
     * 返回唯一的 Realm 名字
     * @return
     */
    @Override
    public String getName() {
        return "myRealm";
    }

    /**
     * 判断此Realm是否支持此Token
     * @param token
     * @return
     */
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof UsernamePasswordToken;
    }

    /**
     * 根据Token 获取认证信息
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //得到用户名
        String username = (String)token.getPrincipal();
        //得到密码
        String password = new String((char[])token.getCredentials());

        //如果用户名错误
        if(!"zhang".equals(username)) {
            throw new UnknownAccountException();
        }

        //如果密码错误
        if(!"123".equals(password)) {
            throw new IncorrectCredentialsException();
        }

        //如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo(username, password, getName());
    }
}
