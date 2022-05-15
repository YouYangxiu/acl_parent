package com.atguigu.security.security;

import com.atguigu.utils.utils.R;
import com.atguigu.utils.utils.ResponseUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.web.ReactiveSortHandlerMethodArgumentResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class TokenLogoutHandler implements LogoutHandler {
    private TokenManager tokenManager;

    public TokenLogoutHandler(TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    private RedisTemplate redisTemplate;

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
        //1.从header中获取到token
        String token = httpServletRequest.getHeader("token");
        //2.token不为空，移除token，从redis删除token
        if (token != null) {
            //移除token主要是在前端操作，不传token的值

            String userInfo = tokenManager.getUserInfoFromToken(token);
            //从redis中删除该用户信息
            redisTemplate.delete(userInfo);
        }
        ResponseUtil.out(httpServletResponse, R.ok());

    }
}
