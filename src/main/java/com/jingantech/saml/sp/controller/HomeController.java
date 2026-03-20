package com.jingantech.saml.sp.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 首页控制器
 * 
 * @author jingantech
 */
@Controller
public class HomeController {

    @Value("${saml.sp.entity-id}")
    private String spEntityId;

    @Value("${saml.sp.acs-location}")
    private String spAcsLocation;

    @Value("${saml.idp.entity-id}")
    private String idpEntityId;

    @Value("${saml.idp.sso-url}")
    private String idpSsoUrl;

    @Value("${server.port}")
    private String serverPort;

    /**
     * 首页
     */
    @GetMapping({"/", "/index"})
    public String index(Model model) {
        model.addAttribute("spEntityId", spEntityId);
        model.addAttribute("spAcsLocation", spAcsLocation);
        model.addAttribute("idpEntityId", idpEntityId);
        model.addAttribute("idpSsoUrl", idpSsoUrl);
        model.addAttribute("spMetadataUrl", "http://localhost:" + serverPort + "/saml/metadata");
        return "index";
    }

}
