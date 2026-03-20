package com.jingantech.saml.sp.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 用户信息控制器
 * 
 * 展示 SAML 认证后的用户信息
 * 
 * @author jingantech
 */
@Controller
@RequestMapping("/user")
public class UserController {

    /**
     * 用户信息页面
     * 
     * @param principal SAML 认证主体
     * @param model 模型
     * @return 用户信息页面
     */
    @GetMapping
    public String userInfo(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        if (principal != null) {
            // 基本信息
            model.addAttribute("nameId", principal.getName());
            model.addAttribute("registrationId", principal.getRelyingPartyRegistrationId());
            
            // SAML 属性 - 转换为 Map<String, Object>
            Map<String, List<Object>> rawAttributes = principal.getAttributes();
            Map<String, Object> attributes = new HashMap<>();
            for (Map.Entry<String, List<Object>> entry : rawAttributes.entrySet()) {
                List<Object> values = entry.getValue();
                if (values != null && !values.isEmpty()) {
                    attributes.put(entry.getKey(), values.size() == 1 ? values.get(0) : values);
                }
            }
            model.addAttribute("attributes", attributes);
            
            // 常用属性提取
            model.addAttribute("userId", getAttribute(principal, "userId"));
            model.addAttribute("tenant", getAttribute(principal, "tenant"));
            model.addAttribute("userApiKey", getAttribute(principal, "userApiKey"));
        }
        return "user";
    }

    /**
     * 获取单个属性值
     */
    private String getAttribute(Saml2AuthenticatedPrincipal principal, String name) {
        try {
            return principal.getFirstAttribute(name);
        } catch (Exception e) {
            return null;
        }
    }

}
