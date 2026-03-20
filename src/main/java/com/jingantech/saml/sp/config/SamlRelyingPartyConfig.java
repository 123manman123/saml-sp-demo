package com.jingantech.saml.sp.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * SAML Relying Party (SP) 配置
 * 
 * 配置 SP 的凭证和 IDP 的信任配置
 * 
 * @author jingantech
 */
@Configuration
public class SamlRelyingPartyConfig {

    private static final Logger log = LoggerFactory.getLogger(SamlRelyingPartyConfig.class);

    @Value("${saml.sp.entity-id}")
    private String spEntityId;

    @Value("${saml.sp.acs-location}")
    private String spAcsLocation;

    @Value("${saml.idp.entity-id}")
    private String idpEntityId;

    @Value("${saml.idp.sso-url}")
    private String idpSsoUrl;

    /**
     * 创建 RelyingPartyRegistrationRepository
     */
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {
        log.info("========== SAML SP 配置初始化开始 ==========");
        log.info("SP Entity ID: {}", spEntityId);
        log.info("SP ACS Location: {}", spAcsLocation);
        log.info("IDP Entity ID: {}", idpEntityId);
        log.info("IDP SSO URL: {}", idpSsoUrl);
        
        // 加载 SP 签名凭证
        Saml2X509Credential signingCredential = loadSigningCredential();
        if (signingCredential != null) {
            log.info("SP 签名凭证加载成功");
        } else {
            log.warn("SP 签名凭证未配置（SP 发起的 AuthnRequest 将不会被签名）");
        }
        
        // 加载 SP 解密凭证
        Saml2X509Credential decryptionCredential = loadDecryptionCredential();
        if (decryptionCredential != null) {
            log.info("SP 解密凭证加载成功");
        } else {
            log.warn("SP 解密凭证未配置（将无法解密 IDP 加密的 Assertion）");
        }
        
        // 加载 IDP 验证凭证
        final Saml2X509Credential idpCredential = loadIdpVerificationCredential();
        if (idpCredential == null) {
            log.error("!!! [严重错误] IDP 验证凭证加载失败！SAML 签名验证将失败 !!!");
        } else {
            X509Certificate cert = (X509Certificate) idpCredential.getCertificate();
            log.info("========== IDP 验证证书信息 ==========");
            log.info("证书主题 (Subject DN): {}", cert.getSubjectDN());
            log.info("证书颁发者 (Issuer DN): {}", cert.getIssuerDN());
            log.info("证书序列号: {}", cert.getSerialNumber());
            log.info("证书有效期: {} ~ {}", cert.getNotBefore(), cert.getNotAfter());
            log.info("证书 SHA-256 指纹: {}", bytesToHex(java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())));
            log.info("证书公钥算法: {}", cert.getPublicKey().getAlgorithm());
            log.info("证书公钥长度: {} bits", cert.getPublicKey().getEncoded().length * 8);
            log.info("======================================");
        }
        
        // 构建 RelyingPartyRegistration
        RelyingPartyRegistration.Builder builder = RelyingPartyRegistration
                .withRegistrationId("ngiam")
                .entityId(spEntityId)
                .assertionConsumerServiceLocation(spAcsLocation);
        
        // SP 签名凭证（如果有效）
        if (signingCredential != null) {
            builder.signingX509Credentials(c -> c.add(signingCredential));
        }
        
        // SP 解密凭证（如果有效）
        if (decryptionCredential != null) {
            builder.decryptionX509Credentials(c -> {
                c.add(decryptionCredential);
                log.info("!!! 解密凭证已添加到 RelyingPartyRegistration: {}", 
                    ((X509Certificate)decryptionCredential.getCertificate()).getSubjectDN());
            });
        }
        
        // IDP 配置
        builder.assertingPartyDetails(party -> {
            party.entityId(idpEntityId)
                 .singleSignOnServiceLocation(idpSsoUrl)
                 .wantAuthnRequestsSigned(false);
            
            // IDP 验证凭证（如果有效）
            if (idpCredential != null) {
                party.verificationX509Credentials(c -> c.add(idpCredential));
                log.info("IDP 验证证书已添加到 RelyingPartyRegistration");
            } else {
                log.error("!!! IDP 验证证书未添加，签名验证必然失败 !!!");
            }
        });
        
        log.info("========== SAML SP 配置初始化完成 ==========");
        
        // 构建最终的 RelyingPartyRegistration 并打印调试信息
        RelyingPartyRegistration registration = builder.build();
        log.info("最终 RelyingPartyRegistration:");
        log.info("  - Registration ID: {}", registration.getRegistrationId());
        log.info("  - SP Entity ID: {}", registration.getEntityId());
        log.info("  - ACS Location: {}", registration.getAssertionConsumerServiceLocation());
        log.info("  - Signing Credentials: {}", registration.getSigningX509Credentials().size());
        log.info("  - Decryption Credentials: {}", registration.getDecryptionX509Credentials().size());
        if (!registration.getDecryptionX509Credentials().isEmpty()) {
            Saml2X509Credential cred = registration.getDecryptionX509Credentials().iterator().next();
            log.info("  - Decryption Certificate: {}", ((X509Certificate)cred.getCertificate()).getSubjectDN());
        }
        
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    /**
     * 加载 SP 签名凭证
     */
    private Saml2X509Credential loadSigningCredential() {
        try {
            Resource certResource = new ClassPathResource("saml/sp-certificate.pem");
            Resource keyResource = new ClassPathResource("saml/sp-private-key.pem");
            
            if (!certResource.exists() || !keyResource.exists()) {
                return null;
            }
            
            // 检查是否是占位符文件
            String certContent = StreamUtils.copyToString(certResource.getInputStream(), StandardCharsets.UTF_8);
            if (certContent.contains("[请替换") || certContent.contains("替换为实际") || certContent.contains("示例")) {
                return null;
            }
            
            // 加载证书
            X509Certificate certificate = loadCertificate(certResource);
            // 加载私钥
            PrivateKey privateKey = loadPrivateKey(keyResource);
            
            if (certificate == null || privateKey == null) {
                return null;
            }
            
            return new Saml2X509Credential(privateKey, certificate, 
                    Saml2X509Credential.Saml2X509CredentialType.SIGNING);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 加载 IDP 验证凭证
     */
    private Saml2X509Credential loadIdpVerificationCredential() {
        try {
            Resource certResource = new ClassPathResource("saml/idp-certificate.pem");
            
            if (!certResource.exists()) {
                log.error("IDP 证书文件不存在: saml/idp-certificate.pem");
                return null;
            }
            
            log.info("找到 IDP 证书文件: saml/idp-certificate.pem");
            
            // 检查是否是占位符文件
            String certContent = StreamUtils.copyToString(certResource.getInputStream(), StandardCharsets.UTF_8);
            if (certContent.contains("[请替换") || certContent.contains("替换为") || certContent.contains("示例")) {
                log.error("IDP 证书文件是占位符，请替换为实际的 IDP 证书");
                return null;
            }
            
            log.info("IDP 证书文件内容长度: {} 字符", certContent.length());
            
            X509Certificate certificate = loadCertificate(certResource);
            if (certificate == null) {
                log.error("IDP 证书解析失败");
                return null;
            }
            
            log.info("IDP 证书解析成功: {}", certificate.getSubjectDN());
            
            return new Saml2X509Credential(certificate, 
                    Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
        } catch (Exception e) {
            log.error("加载 IDP 验证凭证时发生异常", e);
            return null;
        }
    }

    /**
     * 加载 X509 证书
     */
    private X509Certificate loadCertificate(Resource resource) {
        try (InputStream is = resource.getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(is);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 加载私钥（PKCS8 格式）
     * 使用 Java 8 兼容的方式读取输入流
     */
    private PrivateKey loadPrivateKey(Resource resource) {
        try (InputStream is = resource.getInputStream()) {
            // Java 8 兼容方式读取输入流
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] data = new byte[1024];
            int nRead;
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            String privateKeyPEM = new String(buffer.toByteArray(), StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            
            if (privateKeyPEM.isEmpty() || privateKeyPEM.contains("替换为")) {
                return null;
            }
            
            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 字节数组转十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 加载 SP 解密凭证（用于解密 IDP 加密的 Assertion）
     */
    private Saml2X509Credential loadDecryptionCredential() {
        try {
            Resource certResource = new ClassPathResource("saml/sp-encryption-certificate.pem");
            Resource keyResource = new ClassPathResource("saml/sp-encryption-private-key.pem");
            
            if (!certResource.exists() || !keyResource.exists()) {
                log.warn("SP 解密凭证文件不存在");
                return null;
            }
            
            log.info("找到 SP 解密凭证文件");
            
            // 检查是否是占位符文件
            String certContent = StreamUtils.copyToString(certResource.getInputStream(), StandardCharsets.UTF_8);
            if (certContent.contains("[请替换") || certContent.contains("替换为") || certContent.contains("示例")) {
                log.warn("SP 解密凭证是占位符");
                return null;
            }
            
            // 加载证书
            X509Certificate certificate = loadCertificate(certResource);
            // 加载私钥
            PrivateKey privateKey = loadPrivateKey(keyResource);
            
            if (certificate == null || privateKey == null) {
                log.error("SP 解密凭证解析失败");
                return null;
            }
            
            log.info("SP 解密凭证加载成功 - 证书主题: {}", certificate.getSubjectDN());
            
            // 验证私钥和证书是否匹配
            try {
                java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
                byte[] testData = "test".getBytes();
                sig.initSign(privateKey);
                sig.update(testData);
                byte[] signature = sig.sign();
                
                sig.initVerify(certificate.getPublicKey());
                sig.update(testData);
                boolean valid = sig.verify(signature);
                
                if (valid) {
                    log.info("!!! 私钥和证书匹配验证成功 !!!");
                } else {
                    log.error("!!! 私钥和证书不匹配 !!!");
                    return null;
                }
            } catch (Exception e) {
                log.error("验证私钥和证书匹配时发生错误", e);
                return null;
            }
            
            // 设置解密凭证到静态变量供 Filter 使用
            com.jingantech.saml.sp.filter.SamlResponseLoggingFilter.decryptionPrivateKey = privateKey;
            com.jingantech.saml.sp.filter.SamlResponseLoggingFilter.decryptionCertificate = certificate;
            log.info("解密凭证已设置到 SamlResponseLoggingFilter");
            
            // 设置解密凭证到 SamlDecryptionFilter
            com.jingantech.saml.sp.filter.SamlDecryptionFilter.decryptionPrivateKey = privateKey;
            com.jingantech.saml.sp.filter.SamlDecryptionFilter.decryptionCertificate = certificate;
            log.info("解密凭证已设置到 SamlDecryptionFilter");
            
            return new Saml2X509Credential(privateKey, certificate, 
                    Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
        } catch (Exception e) {
            log.error("加载 SP 解密凭证时发生异常", e);
            return null;
        }
    }

}