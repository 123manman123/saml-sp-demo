package com.jingantech.saml.sp.config;

import com.jingantech.saml.sp.filter.SamlDecryptionFilter;
import com.jingantech.saml.sp.filter.SamlResponseLoggingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.core.AuthenticationException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Spring Security 安全配置
 * 
 * 配置 SAML 2.0 认证流程：
 * 1. 首页和静态资源允许匿名访问
 * 2. 用户信息页面需要认证
 * 3. 配置 SAML 登录和登出
 * 
 * @author jingantech
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 添加解密过滤器 - 最先执行
        http.addFilterBefore(new SamlDecryptionFilter(), 
            org.springframework.security.web.access.channel.ChannelProcessingFilter.class);
        
        // 添加日志过滤器
        http.addFilterAfter(new SamlResponseLoggingFilter(), SamlDecryptionFilter.class);
        
        http
            // 授权配置
            .authorizeHttpRequests(authz -> authz
                // 首页和静态资源允许匿名访问
                .antMatchers("/", "/index", "/saml/**").permitAll()
                // 其他请求需要认证
                .anyRequest().authenticated()
            )
            // SAML2 登录配置
            .saml2Login(saml2 -> saml2
                .loginProcessingUrl("/login/saml2/sso/{registrationId}")
                .defaultSuccessUrl("/user", true)
                .failureHandler(samlAuthenticationFailureHandler())
            )
            // 登出配置
            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
            )
            // 禁用 CSRF（开发环境，生产环境建议开启）
            .csrf(csrf -> csrf.disable());
        
        return http.build();
    }

    @Bean
    public AuthenticationFailureHandler samlAuthenticationFailureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, 
                    HttpServletResponse response, AuthenticationException exception) 
                    throws IOException, ServletException {
                
                log.error("========== SAML 认证失败 ==========");
                log.error("异常类型: {}", exception.getClass().getName());
                log.error("异常消息: {}", exception.getMessage());
                
                Throwable cause = exception.getCause();
                while (cause != null) {
                    log.error("原因: {} - {}", cause.getClass().getName(), cause.getMessage());
                    cause = cause.getCause();
                }
                
                log.error("完整堆栈:", exception);
                log.error("==================================");
                
                response.sendRedirect("/?error=true&message=" + 
                    java.net.URLEncoder.encode(exception.getMessage(), "UTF-8"));
            }
        };
    }

}