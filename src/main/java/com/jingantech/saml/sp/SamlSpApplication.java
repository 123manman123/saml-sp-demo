package com.jingantech.saml.sp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * SAML SP Demo 启动类
 * 
 * 作为 SAML 2.0 服务提供者（SP）端，对接 NGIAM IDP 实现单点登录
 * 
 * @author jingantech
 */
@SpringBootApplication
public class SamlSpApplication {

    public static void main(String[] args) {
        SpringApplication.run(SamlSpApplication.class, args);
    }

}
