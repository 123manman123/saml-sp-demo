package com.jingantech.saml.sp.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Base64;

/**
 * SAML 调试过滤器
 * 用于捕获和打印 SAML Request/Response 内容
 */
@Component
@Order(1)
public class SamlDebugFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SamlDebugFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // 只处理 SAML 相关请求
        String requestURI = request.getRequestURI();
        if (requestURI.contains("/saml") || requestURI.contains("/login/saml2")) {
            log.info("========== SAML 请求调试 ==========");
            log.info("请求 URI: {}", requestURI);
            log.info("请求方法: {}", request.getMethod());
            
            // 打印所有参数
            request.getParameterMap().forEach((key, values) -> {
                for (String value : values) {
                    if ("SAMLRequest".equals(key) || "SAMLResponse".equals(key)) {
                        try {
                            String decoded = new String(Base64.getDecoder().decode(value));
                            log.info("参数 {} (Base64 解码后):\n{}", key, formatXml(decoded));
                        } catch (Exception e) {
                            log.info("参数 {} (原始值): {}", key, value.length() > 200 ? value.substring(0, 200) + "..." : value);
                        }
                    } else {
                        log.info("参数 {}: {}", key, value);
                    }
                }
            });
            log.info("==================================");
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String formatXml(String xml) {
        // 简单格式化，限制长度
        if (xml.length() > 5000) {
            return xml.substring(0, 5000) + "\n... (内容过长，已截断)";
        }
        return xml;
    }
}