package com.tongwei.auth.security.rule;

import java.io.IOException;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tongwei.auth.model.AuthUser;
import com.tongwei.auth.security.RememberMeType;
import com.tongwei.auth.util.AESUtil;
import com.tongwei.auth.util.AuthUtil;
import com.tongwei.auth.util.SessionUtil;
import com.tongwei.auth.util.SyncUtil;
import com.tongwei.common.util.MD5Util;

/**
 * @author yangz
 * @date 2018年1月25日 下午6:13:32
 * @description 内置记住规则抽象
 */
public abstract class AbstractRememberMeRule implements RememberMeRule {

    private static Logger logger = LoggerFactory.getLogger(AbstractRememberMeRule.class);

    //返回随机key+userid+时间差
    @Override
    public String generateValue(HttpServletRequest request, RememberMeType type, Integer userId) {
        String key = null;
        if (RememberMeType.HOST == type) { //如果是HOST则据此生成秘钥
            key = MD5Util.md5(request.getRemoteHost());
        } else if (RememberMeType.USER_AGENT == type) { //如果是agent则取得请求头字段,生成秘钥
            String value = request.getHeader("user-agent");
            if (value == null) {
                logger.error("rememberme is not successful, cause by user-agent is null");
                return null;
            }
            key = MD5Util.md5(value);
        } else {
            key = UUID.randomUUID().toString();//否则随机生成秘钥
        }
        //至此,无论如何key都有值
        long cur = System.currentTimeMillis();//取得与格林威治时间的毫秒差值
        String value = key + "_" + userId + "_" + cur; //随机key+userid+时间差
        try {
            return AESUtil.encodeToHex(value);//返回转换的16进制字符串
        } catch (Exception e) {
            logger.error("AUTHUSER encode ex:", e);
        }
        return null;//以上操作失败,返回空
    }



    @Override
    public boolean validate(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            RememberMeType type, int rememberMeExpireTime) {
        String value = findGenerateValue(request);
        if (value == null) {
            return false;
        }
        String decode = "";
        try {
            decode = AESUtil.decodeFromHex(value);
        } catch (Exception e) {
            logger.error("AUTHUSER decode ex:", e);
        }
        String[] datas = decode.split("_");
        if (datas.length == 3) {
            try {
                String key = datas[0];
                Integer userId = Integer.valueOf(datas[1]);
                long start = Long.valueOf(datas[2]);
                switch (type) {
                case NONE:
                    return handleExpireTime(request, response, chain, rememberMeExpireTime, userId, start);
                case HOST:
                    if (key.equals(MD5Util.md5(request.getRemoteHost()))) {
                        return handleExpireTime(request, response, chain, rememberMeExpireTime, userId, start);
                    }
                    break;
                case USER_AGENT:
                    String ua = request.getHeader("user-agent");
                    if (ua != null && key.equals(MD5Util.md5(ua))) {
                        return handleExpireTime(request, response, chain, rememberMeExpireTime, userId, start);
                    }
                    break;
                default:
                    return false;
                }
            } catch (Exception e) {
                logger.error("rememberMe ex:", e);
            }
        }
        return false;
    }

    /**
     * @param request
     * @param response
     * @param chain
     * @param rememberMeExpireTime
     * @param userId
     * @param start
     * @throws IOException
     * @throws ServletException
     * @throws InterruptedException
     */
    private boolean handleExpireTime(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            int rememberMeExpireTime, Integer userId, long start)
            throws IOException, ServletException, InterruptedException {
        long cur = System.currentTimeMillis();
        if ((cur - start) / 1000 < rememberMeExpireTime) {// 未过期
            AuthUser authUser = AuthUtil.getAuthUser(userId);
            if (authUser == null) {
                authUser = SyncUtil.addToRememberMeQueueAndGetAuthUser(userId);
                if (authUser == null) {
                    return false;
                }
            }
            SessionUtil.setUser(authUser.getUser());
            chain.doFilter(request, response);
            return true;
        }
        return false;
    }

}
