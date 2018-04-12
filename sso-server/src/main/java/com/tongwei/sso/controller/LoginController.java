package com.tongwei.sso.controller;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.tongwei.auth.model.User;
import com.tongwei.auth.security.RememberMeType;
import com.tongwei.auth.security.rule.RememberMeRule;
import com.tongwei.common.BaseController;
import com.tongwei.common.exception.AuthenticationExcption;
import com.tongwei.common.model.Result;
import com.tongwei.common.util.ResultUtil;
import com.tongwei.sso.util.AuthService;

/**
 * @author yangz
 * @date 2018年2月26日 上午10:29:53
 * @description 登录注销
 */
@Controller
@ConfigurationProperties(prefix = "sso.sys")
public class LoginController extends BaseController {

    private String successUrl;//成功的url
    
    private String setCookieUrl;//cookie的url

    @Autowired
    AuthService authService; //权限相关接口

    @Autowired
    RememberMeRule rememberMeRule; //记住用户接口

    @PostMapping("/login")
    @ResponseBody
    public Result login(String loginName, String password, String successUrl, String rememberMe, String rememberMeType)
            throws Exception {
        if (StringUtils.isBlank(loginName) || StringUtils.isBlank(password)) {
            return ResultUtil.doFailure("用户名或密码不能为空!");
        }
        User user = null;
        try {
            user = authService.login(loginName, password);//登录
        } catch (AuthenticationExcption e) {
            return ResultUtil.doFailure(e.getMessage());
        }

        if ("null".equals(successUrl) || StringUtils.isBlank(successUrl)) {//如果传入的succesurl为空,则取默认的url
            successUrl = this.successUrl;
        }

        Map<String, String> data = new HashMap<>(2); //初始化两个容量的hashmap

        Cookie[] cookies = request.getCookies(); //得到请求的cookie
        if (cookies != null) {                                      //cookie不为空,则遍历数组,找出name和value
            for (Cookie cookie : cookies) {                 //如果name为AUTHUSER,则将其存入前面的hashmap
                String name = cookie.getName();
                String value = cookie.getValue();
                if ("AUTHUSER".equalsIgnoreCase(name)) {
                    data.put("AUTHUSER", value);
                }
            }
        }

        // 记住我,rememberMe传入on则
        if ("on".equals(rememberMe)) {
            RememberMeType re = RememberMeType.USER_AGENT;
            if ("HOST".equalsIgnoreCase(rememberMeType)) {
                re = RememberMeType.HOST;
            }
            if ("NONE".equalsIgnoreCase(rememberMeType)) {
                re = RememberMeType.NONE;
            }////根据用户id,用户类型生成一个 随机key+userid+时间差 的字符串
            String generateValue = rememberMeRule.generateValue(request, re, user.getId());
            if (generateValue != null) {
                data.put("AUTHUSER", generateValue);//字符串不为空,则放入map
            }
        }
        data.put("setCookieUrl", setCookieUrl);
        data.put("successUrl", successUrl);
        data.put("SESSION", request.getSession().getId());
        //最后将向客户端返回successUrl  cookie的url  session的Id 用户的角色和值
        return ResultUtil.doSuccess(data); //返回200的号码 和数据
    }

    // 注销登录
    @GetMapping(value = "/loginout")
    public String loginout() {// COOKIE策略注销,将AUTHUSER值置空,重定向到根
        authService.loginout();
        Cookie cookie = new Cookie("AUTHUSER", "");
        response.addCookie(cookie);
        return "redirect:/";
    }

    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }

    public String getSetCookieUrl() {
        return setCookieUrl;
    }

    public void setSetCookieUrl(String setCookieUrl) {
        this.setCookieUrl = setCookieUrl;
    }

}