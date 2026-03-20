#!/bin/bash
# ============================================================
# 生成 SAML SP 密钥库和证书脚本 (Linux/Mac)
# ============================================================

echo "========================================"
echo "SAML SP 密钥库生成工具"
echo "========================================"
echo

KEYSTORE_FILE="src/main/resources/saml/sp.jks"
ALIAS="sp"
STOREPASS="changeit"
KEYPASS="changeit"
VALIDITY=365

echo "正在生成密钥库..."
keytool -genkeypair \
    -alias $ALIAS \
    -keyalg RSA \
    -keysize 2048 \
    -validity $VALIDITY \
    -keystore $KEYSTORE_FILE \
    -storepass $STOREPASS \
    -keypass $KEYPASS \
    -dname "CN=samlsp.jingantech.com, OU=Development, O=Jingantech, L=Beijing, ST=Beijing, C=CN"

if [ $? -eq 0 ]; then
    echo
    echo "密钥库生成成功: $KEYSTORE_FILE"
    echo
    echo "正在导出证书..."
    
    # 导出证书（PEM格式）
    keytool -exportcert \
        -alias $ALIAS \
        -keystore $KEYSTORE_FILE \
        -storepass $STOREPASS \
        -rfc \
        > src/main/resources/saml/sp-certificate.pem
    
    if [ $? -eq 0 ]; then
        echo "证书导出成功: src/main/resources/saml/sp-certificate.pem"
    else
        echo "证书导出失败！"
        exit 1
    fi
    
    # 检查是否有 OpenSSL
    if command -v openssl &> /dev/null; then
        echo
        echo "正在导出私钥..."
        
        # 转换为 PKCS12
        keytool -importkeystore \
            -srckeystore $KEYSTORE_FILE \
            -destkeystore sp.p12 \
            -deststoretype PKCS12 \
            -srcstorepass $STOREPASS \
            -deststorepass $STOREPASS 2>/dev/null
        
        # 导出私钥
        openssl pkcs12 -in sp.p12 -nocerts -nodes \
            -out src/main/resources/saml/sp-private-key.pem \
            -passin pass:$STOREPASS 2>/dev/null
        
        # 清理临时文件
        rm -f sp.p12
        
        echo "私钥导出成功: src/main/resources/saml/sp-private-key.pem"
    fi
    
    echo
    echo "========================================"
    echo "证书文件生成完成！"
    echo "- sp.jks: Java 密钥库"
    echo "- sp-certificate.pem: SP 证书"
    echo "- sp-private-key.pem: SP 私钥"
    echo "========================================"
else
    echo "密钥库生成失败！"
    exit 1
fi
