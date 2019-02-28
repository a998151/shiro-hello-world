package com.lemon.shiro.factory;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author YZH
 * @date 2019/2/28 16:14
 */
public class ShiroFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(ShiroFactory.class);

    public static Subject getSubject(String resourcePath){
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        //这中方式一个配置文件对应一个实体
        Factory<SecurityManager> factory = new IniSecurityManagerFactory(resourcePath);

        //2、得到SecurityManager实例 并绑定给SecurityUtils，因为获取所需的主体是从 SecurityUtils 中拿到的
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、从配置文件中得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();

        return subject;
    }

    public static boolean login(Subject subject ,String username , String password){
        UsernamePasswordToken token = new UsernamePasswordToken(username,password);
        try {
            //4、登录，即身份验证
            subject.login(token);
            LOGGER.info("认证成功");
            return true;
        } catch (IncorrectCredentialsException e) {
            System.out.println("登录密码错误. Password for account " + token.getPrincipal() + " was incorrect.");
            return false;
        } catch (ExcessiveAttemptsException e) {
            System.out.println("登录失败次数过多");
            return false;
        } catch (LockedAccountException e) {
            System.out.println("帐号已被锁定. The account for username " + token.getPrincipal() + " was locked.");
            return false;
        } catch (DisabledAccountException e) {
            System.out.println("帐号已被禁用. The account for username " + token.getPrincipal() + " was disabled.");
            return false;
        } catch (ExpiredCredentialsException e) {
            System.out.println("帐号已过期. the account for username " + token.getPrincipal() + "  was expired.");
            return false;
        } catch (UnknownAccountException e) {
            System.out.println("帐号不存在. There is no user with username of " + token.getPrincipal());
            return false;
        } catch (Exception e){
            return false;
        }
    }

    public static void logout(Subject subject){
        subject.logout();
    }
}
