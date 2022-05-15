package com.atguigu.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class TokenManager {
    //1.设置token的有效时长
    private long tokenExpiration = 24 * 60 * 60 * 1000;
    //2.编码密钥
    private final String tokenSingKey = "youyangxiu";

    //3.使用jwt根据用户名生成Token
    public String createToken(String username) {
        String token = Jwts.builder().setSubject(username)
                .setExpiration(new Date(System.currentTimeMillis() + tokenExpiration))
                .signWith(SignatureAlgorithm.ES512, tokenSingKey)
                .compressWith(CompressionCodecs.GZIP)
                .compact();
        return token;
    }

    //4.根据token字符串得到用户信息
    public String getUserInfoFromToken(String token) {
        String userInfo = Jwts.parser().setSigningKey(tokenSingKey).parseClaimsJws(token).getBody().getSubject();
        return userInfo;
    }
}
