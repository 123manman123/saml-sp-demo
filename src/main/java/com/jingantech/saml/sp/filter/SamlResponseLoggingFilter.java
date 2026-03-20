package com.jingantech.saml.sp.filter;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;

/**
 * SAML Response 日志过滤器
 * 用于打印收到的原始 SAML Response，便于调试
 */
public class SamlResponseLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SamlResponseLoggingFilter.class);
    
    // 静态存储解密凭证（在 SecurityConfig 中设置）
    public static java.security.PrivateKey decryptionPrivateKey;
    public static java.security.cert.X509Certificate decryptionCertificate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
            FilterChain filterChain) throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        String method = request.getMethod();
        
        log.info("========== SamlResponseLoggingFilter ==========");
        log.info("Request URI: {}, Method: {}", requestURI, method);
        
        // 只处理 SAML 响应 POST 请求
        if (requestURI.contains("/login/saml2/sso/") && "POST".equalsIgnoreCase(method)) {
            // 直接从请求参数获取（需要在 Spring Security 处理之前）
            String samlResponse = request.getParameter("SAMLResponse");
            String relayState = request.getParameter("RelayState");
            
            log.info("SAMLResponse 参数: {}", samlResponse != null ? "存在, 长度=" + samlResponse.length() : "不存在");
            log.info("RelayState 参数: {}", relayState);
            
            if (samlResponse != null) {
                try {
                    // Base64 解码
                    byte[] decoded = Base64.getDecoder().decode(samlResponse);
                    String xmlResponse = new String(decoded, "UTF-8");
                    
                    log.info("========== 收到 SAML Response ==========");
                    log.info("SAML Response XML:\n{}", xmlResponse);
                    log.info("========================================");
                    
                    // 尝试手动解密来定位错误
                    if (decryptionPrivateKey != null && decryptionCertificate != null) {
                        testDecrypt(decoded);
                    } else {
                        log.warn("解密凭证未设置，跳过手动解密测试");
                    }
                    
                } catch (Exception e) {
                    log.error("解码 SAML Response 失败", e);
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * 手动尝试解密 EncryptedAssertion 来定位具体错误
     */
    private void testDecrypt(byte[] samlResponseBytes) {
        try {
            log.info("========== 开始手动解密测试 ==========");
            
            // 解析 SAML Response
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(new ByteArrayInputStream(samlResponseBytes));
            org.w3c.dom.Element element = doc.getDocumentElement();
            
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            XMLObject xmlObject = unmarshaller.unmarshall(element);
            
            if (!(xmlObject instanceof Response)) {
                log.error("XML 根元素不是 saml2p:Response，而是: {}", xmlObject.getClass().getName());
                return;
            }
            
            Response samlResponse = (Response) xmlObject;
            log.info("SAML Response 解析成功, ID: {}", samlResponse.getID());
            log.info("Assertions 数量: {}", samlResponse.getAssertions().size());
            log.info("EncryptedAssertions 数量: {}", samlResponse.getEncryptedAssertions().size());
            
            if (!samlResponse.getEncryptedAssertions().isEmpty()) {
                EncryptedAssertion encryptedAssertion = samlResponse.getEncryptedAssertions().get(0);
                log.info("找到 EncryptedAssertion, 开始解密...");
                
                // 获取加密数据信息
                if (encryptedAssertion.getEncryptedData() != null) {
                    String encAlgorithm = encryptedAssertion.getEncryptedData().getEncryptionMethod() != null 
                        ? encryptedAssertion.getEncryptedData().getEncryptionMethod().getAlgorithm() : "未知";
                    log.info("数据加密算法: {}", encAlgorithm);
                    
                    if (encryptedAssertion.getEncryptedData().getKeyInfo() != null) {
                        log.info("KeyInfo 存在");
                        if (encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys() != null 
                                && !encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().isEmpty()) {
                            String keyEncAlgorithm = encryptedAssertion.getEncryptedData().getKeyInfo()
                                .getEncryptedKeys().get(0).getEncryptionMethod() != null 
                                ? encryptedAssertion.getEncryptedData().getKeyInfo()
                                    .getEncryptedKeys().get(0).getEncryptionMethod().getAlgorithm() : "未知";
                            log.info("密钥加密算法: {}", keyEncAlgorithm);
                        }
                    }
                }
                
                // 创建解密凭证
                org.opensaml.security.credential.BasicCredential cred = 
                    new org.opensaml.security.credential.BasicCredential(
                        decryptionCertificate.getPublicKey(), decryptionPrivateKey);
                
                KeyInfoCredentialResolver keyResolver = new CollectionKeyInfoCredentialResolver(
                        Collections.singletonList(cred));
                
                Decrypter decrypter = new Decrypter(null, keyResolver, new InlineEncryptedKeyResolver());
                
                // 尝试解密
                try {
                    log.info("开始执行解密...");
                    org.opensaml.core.xml.XMLObject xmlObj = 
                        decrypter.decryptData(encryptedAssertion.getEncryptedData());
                    if (xmlObj instanceof org.opensaml.saml.saml2.core.Assertion) {
                        org.opensaml.saml.saml2.core.Assertion assertion = 
                            (org.opensaml.saml.saml2.core.Assertion) xmlObj;
                        log.info("!!! 解密成功 !!! Assertion ID: {}", assertion.getID());
                        log.info("解密后的 Assertion Subject: {}", 
                            assertion.getSubject() != null && assertion.getSubject().getNameID() != null 
                                ? assertion.getSubject().getNameID().getValue() : "无");
                    } else {
                        log.info("!!! 解密成功 !!! 返回类型: {}", xmlObj.getClass().getName());
                    }
                    
                } catch (DecryptionException e) {
                    log.error("!!! 解密失败 !!!");
                    log.error("解密异常类型: {}", e.getClass().getName());
                    log.error("解密异常消息: {}", e.getMessage());
                    Throwable cause = e.getCause();
                    int depth = 0;
                    while (cause != null && depth < 10) {
                        log.error("原因[{}]: {} - {}", depth, cause.getClass().getName(), cause.getMessage());
                        cause = cause.getCause();
                        depth++;
                    }
                    log.error("解密异常堆栈:", e);
                }
            } else {
                log.warn("没有找到 EncryptedAssertion");
            }
            
            log.info("========== 手动解密测试结束 ==========");
            
        } catch (Exception e) {
            log.error("手动解密测试过程中发生异常", e);
        }
    }
}
