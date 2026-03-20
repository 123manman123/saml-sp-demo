@echo off
REM ============================================================
REM 生成 SAML SP 密钥库和证书脚本 (Windows)
REM ============================================================

echo ========================================
echo SAML SP 密钥库生成工具
echo ========================================
echo.

set KEYSTORE_FILE=src\main\resources\saml\sp.jks
set ALIAS=sp
set STOREPASS=changeit
set KEYPASS=changeit
set VALIDITY=365

echo 正在生成密钥库...
keytool -genkeypair ^
    -alias %ALIAS% ^
    -keyalg RSA ^
    -keysize 2048 ^
    -validity %VALIDITY% ^
    -keystore %KEYSTORE_FILE% ^
    -storepass %STOREPASS% ^
    -keypass %KEYPASS% ^
    -dname "CN=samlsp.jingantech.com, OU=Development, O=Jingantech, L=Beijing, ST=Beijing, C=CN"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo 密钥库生成成功: %KEYSTORE_FILE%
    echo.
    echo 正在导出证书...
    
    REM 导出证书（PEM格式）
    keytool -exportcert ^
        -alias %ALIAS% ^
        -keystore %KEYSTORE_FILE% ^
        -storepass %STOREPASS% ^
        -rfc ^
        > src\main\resources\saml\sp-certificate.pem
    
    if %ERRORLEVEL% EQU 0 (
        echo 证书导出成功: src\main\resources\saml\sp-certificate.pem
    ) else (
        echo 证书导出失败！
    )
    
    echo.
    echo ========================================
    echo 接下来请手动导出私钥（需要 OpenSSL）:
    echo.
    echo 1. 将 JKS 转换为 PKCS12:
    echo    keytool -importkeystore -srckeystore src\main\resources\saml\sp.jks -destkeystore sp.p12 -deststoretype PKCS12 -srcstorepass changeit -deststorepass changeit
    echo.
    echo 2. 使用 OpenSSL 导出私钥:
    echo    openssl pkcs12 -in sp.p12 -nocerts -nodes -out src\main\resources\saml\sp-private-key.pem -passin pass:changeit
    echo.
    echo 3. 清理临时文件:
    echo    del sp.p12
    echo ========================================
) else (
    echo 密钥库生成失败！
    exit /b 1
)

pause
