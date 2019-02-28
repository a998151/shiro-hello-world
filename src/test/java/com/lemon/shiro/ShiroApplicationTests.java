package com.lemon.shiro;

import com.lemon.shiro.factory.ShiroFactory;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ShiroApplicationTests {

    private static final Logger LOGGER = LoggerFactory.getLogger(ShiroApplicationTests.class);

    //配置文件 realm
    @Test
    public void contextLoads() {

        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        //这中方式一个配置文件对应一个实体
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");

        //2、得到SecurityManager实例 并绑定给SecurityUtils，因为获取所需的主体是从 SecurityUtils 中拿到的
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、从配置文件中得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        try {
            //4、登录，即身份验证
            subject.login(token);
        } catch (AuthenticationException e) {
            //5、身份验证失败
            LOGGER.error("认证失败");
        }

        Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录

        //6、退出
        subject.logout();
    }

    //个人 realm
    @Test
    public void test1() {
        Subject subject = ShiroFactory.getSubject("classpath:shiro-realm.ini");
        ShiroFactory.login(subject, "zhang1", "123");
        ShiroFactory.logout(subject);
    }

    //数据库方式 realm
    @Test
    public void test2() {
        Subject subject = ShiroFactory.getSubject("classpath:shiro-jdbc-realm.ini");
        ShiroFactory.login(subject, "zhang", "123");
        ShiroFactory.logout(subject);
    }

}
