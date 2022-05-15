package com.atguigu.security.config;

import com.atguigu.security.filter.TokenAuthFilter;
import com.atguigu.security.filter.TokenLoginFilter;
import com.atguigu.security.security.DefaultPasswordEncoder;
import com.atguigu.security.security.TokenLogoutHandler;
import com.atguigu.security.security.TokenManager;
import com.atguigu.security.security.UnAuthEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;
    private DefaultPasswordEncoder defaultPasswordEncoder;
    private UserDetailsService userDetailsService;

    @Autowired
    public TokenWebSecurityConfig(TokenManager tokenManager, RedisTemplate redisTemplate, DefaultPasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
        this.defaultPasswordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    //设置退出的地址和token，饿第三操作地址
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling().authenticationEntryPoint(new UnAuthEntryPoint())//没有权限访问
                .and().csrf().disable() //禁用csrf
                .authorizeRequests().anyRequest().authenticated()
                .and().logout().logoutUrl("/admin/acl/index/logout") //退出的路径
                .addLogoutHandler(new TokenLogoutHandler(tokenManager, redisTemplate))
                .and().addFilter(new TokenLoginFilter(tokenManager, redisTemplate, authenticationManager()))
                .addFilter(new TokenAuthFilter(authenticationManager(), tokenManager, redisTemplate))
                .httpBasic();
    }

    //调用userDetailsService和密码处理
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }


    //不进行认证的地址
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/api/**");
    }
}
