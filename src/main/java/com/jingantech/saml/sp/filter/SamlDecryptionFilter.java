package com.jingantech.saml.sp.filter;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.security.credential.BasicCredential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * SAML 解密过滤器
 * 
 * 在 Spring Security 处理之前，解密 EncryptedAssertion 并将其转换为普通 Assertion
 * 这样 Spring Security 就能看到解密后的 Assertion
 */
public class SamlDecryptionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SamlDecryptionFilter.class);
    
    // 静态存储解密凭证
    public static PrivateKey decryptionPrivateKey;
    public static X509Certificate decryptionCertificate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
            FilterChain filterChain) throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        String method = request.getMethod();
        
        // 只处理 SAML 响应 POST 请求
        if (requestURI.contains("/login/saml2/sso/") && "POST".equalsIgnoreCase(method)) {
            String samlResponse = request.getParameter("SAMLResponse");
            
            if (samlResponse != null && decryptionPrivateKey != null && decryptionCertificate != null) {
                try {
                    // 解码并解析 SAML Response
                    byte[] decoded = Base64.getDecoder().decode(samlResponse);
                    Response samlResp = parseSamlResponse(decoded);
                    
                    if (samlResp != null && !samlResp.getEncryptedAssertions().isEmpty() 
                            && samlResp.getAssertions().isEmpty()) {
                        
                        log.info("========== 解密 EncryptedAssertion ==========");
                        log.info("Response ID: {}", samlResp.getID());
                        log.info("EncryptedAssertions 数量: {}", samlResp.getEncryptedAssertions().size());
                        
                        // 解密所有 EncryptedAssertion
                        boolean decrypted = false;
                        for (EncryptedAssertion encryptedAssertion : samlResp.getEncryptedAssertions()) {
                            Assertion assertion = decryptAssertion(encryptedAssertion);
                            if (assertion != null) {
                                samlResp.getAssertions().add(assertion);
                                log.info("解密成功！Assertion ID: {}", assertion.getID());
                                decrypted = true;
                            }
                        }
                        
                        if (decrypted) {
                            // 清空 EncryptedAssertions 列表
                            samlResp.getEncryptedAssertions().clear();
                            
                            // 将修改后的 Response 重新序列化
                            String newXml = serializeResponse(samlResp);
                            String newSamlResponse = Base64.getEncoder().encodeToString(newXml.getBytes("UTF-8"));
                            
                            log.info("解密后 Assertions 数量: {}", samlResp.getAssertions().size());
                            log.info("========== 解密完成，包装请求 ==========");
                            
                            // 创建包装请求
                            request = new SamlRequestWrapper(request, newSamlResponse);
                        }
                    }
                } catch (Exception e) {
                    log.error("解密处理失败", e);
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    /**
     * 解析 SAML Response
     */
    private Response parseSamlResponse(byte[] samlResponseBytes) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(new ByteArrayInputStream(samlResponseBytes));
            org.w3c.dom.Element element = doc.getDocumentElement();
            
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            XMLObject xmlObject = unmarshaller.unmarshall(element);
            
            if (xmlObject instanceof Response) {
                return (Response) xmlObject;
            }
        } catch (Exception e) {
            log.error("解析 SAML Response 失败", e);
        }
        return null;
    }
    
    /**
     * 解密 EncryptedAssertion
     */
    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        try {
            BasicCredential cred = new BasicCredential(
                decryptionCertificate.getPublicKey(), decryptionPrivateKey);
            
            KeyInfoCredentialResolver keyResolver = new CollectionKeyInfoCredentialResolver(
                Collections.singletonList(cred));
            
            Decrypter decrypter = new Decrypter(null, keyResolver, new InlineEncryptedKeyResolver());
            
            XMLObject xmlObj = decrypter.decryptData(encryptedAssertion.getEncryptedData());
            if (xmlObj instanceof Assertion) {
                return (Assertion) xmlObj;
            }
        } catch (Exception e) {
            log.error("解密 Assertion 失败", e);
        }
        return null;
    }
    
    /**
     * 序列化 Response 为 XML
     */
    private String serializeResponse(Response response) throws Exception {
        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
        Marshaller marshaller = marshallerFactory.getMarshaller(response);
        org.w3c.dom.Element element = marshaller.marshall(response);
        
        // 转换为字符串
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(element), new StreamResult(writer));
        return writer.toString();
    }
    
    /**
     * 自定义请求包装器，用于替换 SAMLResponse 参数
     */
    private static class SamlRequestWrapper extends HttpServletRequestWrapper {
        private final String newSamlResponse;
        private Map<String, String[]> modifiedParams;
        
        public SamlRequestWrapper(HttpServletRequest request, String newSamlResponse) {
            super(request);
            this.newSamlResponse = newSamlResponse;
            this.modifiedParams = new HashMap<>(request.getParameterMap());
            this.modifiedParams.put("SAMLResponse", new String[]{newSamlResponse});
        }
        
        @Override
        public String getParameter(String name) {
            if ("SAMLResponse".equals(name)) {
                return newSamlResponse;
            }
            return super.getParameter(name);
        }
        
        @Override
        public Map<String, String[]> getParameterMap() {
            return modifiedParams;
        }
        
        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(modifiedParams.keySet());
        }
        
        @Override
        public String[] getParameterValues(String name) {
            if ("SAMLResponse".equals(name)) {
                return new String[]{newSamlResponse};
            }
            return super.getParameterValues(name);
        }
    }
}
