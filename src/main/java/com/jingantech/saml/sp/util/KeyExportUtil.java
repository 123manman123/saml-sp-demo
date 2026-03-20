package com.jingantech.saml.sp.util;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Base64;

/**
 * 密钥导出工具
 * 用于从 JKS 密钥库导出私钥
 */
public class KeyExportUtil {

    public static void main(String[] args) throws Exception {
        String keystorePath = "sp-encryption.jks";
        String storePass = "changeit";
        String keyPass = "changeit";
        String alias = "sp-encryption";
        
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, storePass.toCharArray());
        }
        
        PrivateKey privateKey = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        Certificate cert = ks.getCertificate(alias);
        
        // 导出私钥 (PKCS8 格式)
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n" +
                "-----END PRIVATE KEY-----";
        
        // 导出证书
        String certPEM = "-----BEGIN CERTIFICATE-----\n" +
                Base64.getEncoder().encodeToString(cert.getEncoded()) + "\n" +
                "-----END CERTIFICATE-----";
        
        try (FileWriter fw = new FileWriter("src/main/resources/saml/sp-encryption-private-key.pem")) {
            fw.write(privateKeyPEM);
        }
        
        System.out.println("私钥已导出到: src/main/resources/saml/sp-encryption-private-key.pem");
        System.out.println("\n证书内容:\n" + certPEM);
    }
}
