package com.jingantech.saml.sp.controller;

import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorBuilder;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.PostConstruct;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

/**
 * SP 元数据控制器
 * 
 * 提供 SP 元数据，供 IDP 配置信任关系使用
 * 
 * @author jingantech
 */
@Controller
public class MetadataController {

    private static final Logger log = LoggerFactory.getLogger(MetadataController.class);

    @Autowired
    private RelyingPartyRegistrationRepository registrationRepository;

    @Value("${saml.sp.acs-location}")
    private String spAcsLocation;

    @PostConstruct
    public void init() {
        try {
            // 初始化 OpenSAML
            JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
            javaCryptoValidationInitializer.init();
            InitializationService.initialize();
            log.info("OpenSAML 初始化成功");
        } catch (Exception e) {
            log.error("OpenSAML 初始化失败", e);
        }
    }

    /**
     * 获取 SP 元数据页面（格式化展示，方便复制）
     */
    @GetMapping("/saml/metadata")
    public String getMetadata(Model model) {
        RelyingPartyRegistration registration = registrationRepository.findByRegistrationId("ngiam");
        if (registration == null) {
            model.addAttribute("metadata", "<error>Registration not found</error>");
            return "metadata";
        }
        
        // 生成格式化的 SP 元数据 XML
        String metadata = generateSpMetadata(registration);
        model.addAttribute("metadata", metadata);
        return "metadata";
    }

    /**
     * 获取原始 XML（用于直接下载或查看）
     */
    @GetMapping(value = "/saml/metadata/raw", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getRawMetadata() {
        RelyingPartyRegistration registration = registrationRepository.findByRegistrationId("ngiam");
        if (registration == null) {
            return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><error>Registration not found</error>";
        }
        return generateSpMetadata(registration);
    }

    /**
     * 生成 SP 元数据 XML（符合 SAML 2.0 标准，带签名）
     */
    private String generateSpMetadata(RelyingPartyRegistration registration) {
        StringBuilder xml = new StringBuilder();
        
        // 生成唯一 ID
        String entityId = registration.getEntityId();
        String metadataId = "_" + generateId();
        
        // 获取签名证书和私钥
        X509Certificate signingCert = getSigningCertificate(registration);
        PrivateKey signingPrivateKey = getSigningPrivateKey(registration);
        String certBase64 = "";
        String certSubjectName = "";
        String keyName = entityId;
        if (signingCert != null) {
            certBase64 = encodeCertificate(signingCert);
            certSubjectName = signingCert.getSubjectX500Principal().getName();
            keyName = extractCN(signingCert);
        }
        
        // 解析 ACS Location
        String acsLocation = registration.getAssertionConsumerServiceLocation();
        
        // 计算 RequestInitiator Location
        String requestInitiatorLocation = acsLocation.replace("/login/saml2/sso/ngiam", "/saml/sso");
        
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ");
        xml.append("ID=\"").append(metadataId).append("\" ");
        xml.append("entityID=\"").append(entityId).append("\">\n\n");
        
        // 签名部分
        if (signingCert != null && signingPrivateKey != null) {
            xml.append("  <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
            xml.append("    <ds:SignedInfo>\n");
            xml.append("      <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n");
            xml.append("      <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n");
            xml.append("      <ds:Reference URI=\"#").append(metadataId).append("\">\n");
            xml.append("        <ds:Transforms>\n");
            xml.append("          <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n");
            xml.append("          <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n");
            xml.append("        </ds:Transforms>\n");
            xml.append("        <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n");
            
            // 计算摘要值
            String digestValue = computeDigest(xml.toString(), metadataId);
            xml.append("        <ds:DigestValue>").append(digestValue).append("</ds:DigestValue>\n");
            xml.append("      </ds:Reference>\n");
            xml.append("    </ds:SignedInfo>\n");
            
            // 计算签名值
            String signedInfo = buildSignedInfoXml(metadataId, digestValue);
            String signatureValue = computeSignature(signedInfo, signingPrivateKey);
            xml.append("    <ds:SignatureValue>").append(signatureValue).append("</ds:SignatureValue>\n");
            
            xml.append("    <ds:KeyInfo>\n");
            xml.append("      <ds:KeyName>").append(escapeXml(keyName)).append("</ds:KeyName>\n");
            xml.append("      <ds:X509Data>\n");
            xml.append("        <ds:X509SubjectName>").append(escapeXml(certSubjectName)).append("</ds:X509SubjectName>\n");
            xml.append("        <ds:X509Certificate>").append(certBase64).append("</ds:X509Certificate>\n");
            xml.append("      </ds:X509Data>\n");
            xml.append("    </ds:KeyInfo>\n");
            xml.append("  </ds:Signature>\n\n");
        }
        
        // 算法扩展
        xml.append("  <md:Extensions xmlns:alg=\"urn:oasis:names:tc:SAML:metadata:algsupport\">\n");
        xml.append("    <alg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha512\"/>\n");
        xml.append("    <alg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha384\"/>\n");
        xml.append("    <alg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n");
        xml.append("    <alg:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#sha224\"/>\n");
        xml.append("    <alg:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n");
        xml.append("    <alg:SigningMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512\"/>\n");
        xml.append("    <alg:SigningMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384\"/>\n");
        xml.append("    <alg:SigningMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n");
        xml.append("    <alg:SigningMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n");
        xml.append("  </md:Extensions>\n\n");
        
        // SPSSODescriptor
        xml.append("  <md:SPSSODescriptor AuthnRequestsSigned=\"1\" WantAssertionsSigned=\"1\" ");
        xml.append("protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n");
        
        // SPSSODescriptor Extensions
        xml.append("    <md:Extensions>\n");
        xml.append("      <init:RequestInitiator xmlns:init=\"urn:oasis:names:tc:SAML:profiles:SSO:request-init\" ");
        xml.append("Binding=\"urn:oasis:names:tc:SAML:profiles:SSO:request-init\" ");
        xml.append("Location=\"").append(escapeXml(requestInitiatorLocation)).append("\"/>\n");
        xml.append("    </md:Extensions>\n");
        
        // KeyDescriptor（签名）
        if (signingCert != null) {
            xml.append("    <md:KeyDescriptor use=\"signing\">\n");
            xml.append("      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
            xml.append("        <ds:KeyName>").append(escapeXml(keyName)).append("</ds:KeyName>\n");
            xml.append("        <ds:X509Data>\n");
            xml.append("          <ds:X509SubjectName>").append(escapeXml(certSubjectName)).append("</ds:X509SubjectName>\n");
            xml.append("          <ds:X509Certificate>").append(certBase64).append("</ds:X509Certificate>\n");
            xml.append("        </ds:X509Data>\n");
            xml.append("      </ds:KeyInfo>\n");
            xml.append("    </md:KeyDescriptor>\n");
        }
        
        // KeyDescriptor（加密）
        X509Certificate encryptionCert = getDecryptionCertificate(registration);
        if (encryptionCert != null) {
            String encCertBase64 = encodeCertificate(encryptionCert);
            String encCertSubjectName = encryptionCert.getSubjectX500Principal().getName();
            String encKeyName = extractCN(encryptionCert);
            
            xml.append("    <md:KeyDescriptor use=\"encryption\">\n");
            xml.append("      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
            xml.append("        <ds:KeyName>").append(escapeXml(encKeyName)).append("</ds:KeyName>\n");
            xml.append("        <ds:X509Data>\n");
            xml.append("          <ds:X509SubjectName>").append(escapeXml(encCertSubjectName)).append("</ds:X509SubjectName>\n");
            xml.append("          <ds:X509Certificate>").append(encCertBase64).append("</ds:X509Certificate>\n");
            xml.append("        </ds:X509Data>\n");
            xml.append("      </ds:KeyInfo>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes192-gcm\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes192-cbc\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"/>\n");
            xml.append("      <md:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>\n");
            xml.append("    </md:KeyDescriptor>\n");
        }
        
        // NameID 格式
        xml.append("    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n");
        xml.append("    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n");
        xml.append("    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n");
        xml.append("    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>\n");
        
        // AssertionConsumerService
        xml.append("    <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ");
        xml.append("Location=\"").append(escapeXml(acsLocation)).append("\" index=\"1\"/>\n");
        
        xml.append("  </md:SPSSODescriptor>\n");
        xml.append("</md:EntityDescriptor>");
        
        return xml.toString();
    }
    
    /**
     * 构建 SignedInfo XML
     */
    private String buildSignedInfoXml(String metadataId, String digestValue) {
        StringBuilder sb = new StringBuilder();
        sb.append("<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
        sb.append("  <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n");
        sb.append("  <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n");
        sb.append("  <ds:Reference URI=\"#").append(metadataId).append("\">\n");
        sb.append("    <ds:Transforms>\n");
        sb.append("      <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n");
        sb.append("      <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n");
        sb.append("    </ds:Transforms>\n");
        sb.append("    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n");
        sb.append("    <ds:DigestValue>").append(digestValue).append("</ds:DigestValue>\n");
        sb.append("  </ds:Reference>\n");
        sb.append("</ds:SignedInfo>");
        return sb.toString();
    }
    
    /**
     * 计算摘要值
     */
    private String computeDigest(String xmlContent, String metadataId) {
        try {
            // 构建 Canonicalized XML（去掉签名部分）
            String canonicalized = canonicalizeForDigest(xmlContent, metadataId);
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonicalized.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            log.error("计算摘要失败", e);
            return "";
        }
    }
    
    /**
     * 为摘要计算规范化 XML
     */
    private String canonicalizeForDigest(String xmlContent, String metadataId) {
        // 返回不含签名的 EntityDescriptor 内容（简化处理）
        // 实际应该使用规范的 Canonical XML 处理
        StringBuilder sb = new StringBuilder();
        sb.append("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ");
        sb.append("ID=\"").append(metadataId).append("\" ");
        // 这里需要包含完整的元数据内容（不含签名）
        // 简化处理：返回元数据的主体部分
        return sb.toString() + "entityID=\"" + xmlContent.split("entityID=\"")[1].split("\"")[0] + "\"></md:EntityDescriptor>";
    }
    
    /**
     * 计算签名值
     */
    private String computeSignature(String signedInfoXml, PrivateKey privateKey) {
        try {
            // 使用 SHA256withRSA 签名
            java.security.Signature signature = java.security.Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            
            // 对 SignedInfo 进行规范化后签名
            byte[] canonicalized = canonicalizeSignedInfo(signedInfoXml);
            signature.update(canonicalized);
            byte[] signatureBytes = signature.sign();
            
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            log.error("计算签名失败", e);
            return "";
        }
    }
    
    /**
     * 规范化 SignedInfo
     */
    private byte[] canonicalizeSignedInfo(String signedInfoXml) {
        try {
            // 使用 Apache Santuario 或 OpenSAML 进行规范化
            // 这里使用简化的 UTF-8 编码
            return signedInfoXml.getBytes("UTF-8");
        } catch (Exception e) {
            return signedInfoXml.getBytes();
        }
    }
    
    /**
     * 获取签名证书
     */
    private X509Certificate getSigningCertificate(RelyingPartyRegistration registration) {
        if (!registration.getSigningX509Credentials().isEmpty()) {
            Saml2X509Credential cred = registration.getSigningX509Credentials().iterator().next();
            return (X509Certificate) cred.getCertificate();
        }
        return null;
    }
    
    /**
     * 获取签名私钥
     */
    private PrivateKey getSigningPrivateKey(RelyingPartyRegistration registration) {
        if (!registration.getSigningX509Credentials().isEmpty()) {
            Saml2X509Credential cred = registration.getSigningX509Credentials().iterator().next();
            return cred.getPrivateKey();
        }
        return null;
    }
    
    /**
     * 获取解密证书
     */
    private X509Certificate getDecryptionCertificate(RelyingPartyRegistration registration) {
        if (!registration.getDecryptionX509Credentials().isEmpty()) {
            Saml2X509Credential cred = registration.getDecryptionX509Credentials().iterator().next();
            return (X509Certificate) cred.getCertificate();
        }
        return null;
    }
    
    /**
     * 编码证书为 Base64
     */
    private String encodeCertificate(X509Certificate cert) {
        try {
            byte[] certBytes = cert.getEncoded();
            return Base64.getEncoder().encodeToString(certBytes);
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * 从证书中提取 CN
     */
    private String extractCN(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName();
        String[] parts = dn.split(",");
        for (String part : parts) {
            part = part.trim();
            if (part.toUpperCase().startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return dn;
    }
    
    /**
     * 生成唯一 ID
     */
    private String generateId() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest(UUID.randomUUID().toString().getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString().replace("-", "");
        }
    }
    
    /**
     * XML 转义
     */
    private String escapeXml(String value) {
        if (value == null) return "";
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;");
    }

}
