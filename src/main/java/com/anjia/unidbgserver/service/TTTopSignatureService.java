package com.anjia.unidbgserver.service;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

/**
 * TTTopSignature 服务 - AWS Signature V4 实现
 *
 * 基于豆包应用中的 TTTopSignature 类
 * 使用 AWS Signature Version 4 签名算法
 */
@Service
public class TTTopSignatureService {

    private static final String ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE_NAME = "execute-api";
    private static final String REGION_NAME = "cn-north-1";

    // TODO: 这些密钥需要从 frida 捕获或逆向分析获取
    private String accessKey = "AKIAIOSFODNN7EXAMPLE";  // 占位符
    private String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";  // 占位符

    /**
     * 生成签名
     */
    public String generateSignature(String method, String uri,
                                    Map<String, String> queryParams,
                                    Map<String, String> headers,
                                    String payload,
                                    String dateTime) {
        try {
            // 1. 准备规范请求
            String canonicalRequest = prepareCanonicalRequest(method, uri, queryParams, headers, payload);

            // 2. 准备待签名字符串
            String dateStamp = dateTime.substring(0, 8); // YYYYMMDD
            String stringToSign = prepareStringToSign(canonicalRequest, dateTime, dateStamp);

            // 3. 计算签名
            String signature = calculateSignature(stringToSign, dateStamp);

            return signature;
        } catch (Exception e) {
            throw new RuntimeException("生成签名失败", e);
        }
    }

    /**
     * 生成授权头
     */
    public String generateAuthorizationHeader(String method, String uri,
                                              Map<String, String> queryParams,
                                              Map<String, String> headers,
                                              String payload,
                                              String dateTime) {
        String dateStamp = dateTime.substring(0, 8);
        String signature = generateSignature(method, uri, queryParams, headers, payload, dateTime);

        String credentialScope = dateStamp + "/" + REGION_NAME + "/" + SERVICE_NAME + "/aws4_request";
        String signedHeaders = getSignedHeadersString(headers);

        return String.format("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
            ALGORITHM, accessKey, credentialScope, signedHeaders, signature);
    }

    /**
     * 1. 准备规范请求
     *
     * 格式:
     * HTTPMethod + "\n" +
     * CanonicalURI + "\n" +
     * CanonicalQueryString + "\n" +
     * CanonicalHeaders + "\n" +
     * SignedHeaders + "\n" +
     * HashedPayload
     */
    private String prepareCanonicalRequest(String method, String uri,
                                          Map<String, String> queryParams,
                                          Map<String, String> headers,
                                          String payload) throws Exception {
        String canonicalURI = uri.isEmpty() ? "/" : uri;
        String canonicalQueryString = getCanonicalQueryString(queryParams);
        String canonicalHeaders = getCanonicalHeaders(headers);
        String signedHeaders = getSignedHeadersString(headers);
        String hashedPayload = sha256Hex(payload);

        return String.format("%s\n%s\n%s\n%s\n%s\n%s",
            method, canonicalURI, canonicalQueryString,
            canonicalHeaders, signedHeaders, hashedPayload);
    }

    /**
     * 2. 准备待签名字符串
     *
     * 格式:
     * Algorithm + "\n" +
     * RequestDateTime + "\n" +
     * CredentialScope + "\n" +
     * HashedCanonicalRequest
     */
    private String prepareStringToSign(String canonicalRequest, String dateTime, String dateStamp)
            throws Exception {
        String credentialScope = dateStamp + "/" + REGION_NAME + "/" + SERVICE_NAME + "/aws4_request";
        String hashedCanonicalRequest = sha256Hex(canonicalRequest);

        return String.format("%s\n%s\n%s\n%s",
            ALGORITHM, dateTime, credentialScope, hashedCanonicalRequest);
    }

    /**
     * 3. 计算签名
     *
     * 使用一系列 HMAC-SHA256 操作生成签名密钥，然后签名字符串
     */
    private String calculateSignature(String stringToSign, String dateStamp) throws Exception {
        // kDate = HMAC("AWS4" + secretKey, date)
        byte[] kDate = hmacSHA256(("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8), dateStamp);

        // kRegion = HMAC(kDate, region)
        byte[] kRegion = hmacSHA256(kDate, REGION_NAME);

        // kService = HMAC(kRegion, service)
        byte[] kService = hmacSHA256(kRegion, SERVICE_NAME);

        // kSigning = HMAC(kService, "aws4_request")
        byte[] kSigning = hmacSHA256(kService, "aws4_request");

        // signature = HMAC(kSigning, stringToSign)
        byte[] signature = hmacSHA256(kSigning, stringToSign);

        return bytesToHex(signature);
    }

    /**
     * 获取规范查询字符串
     */
    private String getCanonicalQueryString(Map<String, String> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }

        return params.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(e -> urlEncode(e.getKey()) + "=" + urlEncode(e.getValue()))
            .collect(Collectors.joining("&"));
    }

    /**
     * 获取规范头部字符串
     */
    private String getCanonicalHeaders(Map<String, String> headers) {
        return headers.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(e -> e.getKey().toLowerCase() + ":" + e.getValue().trim() + "\n")
            .collect(Collectors.joining());
    }

    /**
     * 获取已签名头部列表
     */
    private String getSignedHeadersString(Map<String, String> headers) {
        return headers.keySet().stream()
            .map(String::toLowerCase)
            .sorted()
            .collect(Collectors.joining(";"));
    }

    /**
     * SHA-256 哈希，返回十六进制字符串
     */
    private String sha256Hex(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * HMAC-SHA256
     */
    private byte[] hmacSHA256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
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
     * URL 编码
     */
    private String urlEncode(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8")
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
        } catch (Exception e) {
            return value;
        }
    }

    // Getters and Setters for configuration
    public void setAccessKey(String accessKey) {
        this.accessKey = accessKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public void setRegionName(String regionName) {
        // 可选：支持动态设置 region
    }

    public void setServiceName(String serviceName) {
        // 可选：支持动态设置 service
    }
}
