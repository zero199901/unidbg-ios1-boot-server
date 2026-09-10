package com.anjia.unidbgserver.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * 统一加密服务
 * 整合所有豆包加密字段生成功能
 */
@Service
public class UnifiedCryptoService {

    @Autowired
    private LocationEncryptService locationEncryptService;

    @Autowired
    private TTTopSignatureService signatureService;

    @Autowired
    private GorgonServiceWorker gorgonServiceWorker;

    /**
     * 生成完整的豆包请求
     * 包含所有必需的加密字段和签名
     *
     * @param url 请求 URL（含查询参数）
     * @param body 请求体 JSON
     * @param locationData 位置信息（可选）
     * @return 包含所有加密字段和签名的完整请求数据
     */
    public DoubaoRequest generateCompleteRequest(String url, String body, Map<String, Object> locationData)
            throws Exception {

        DoubaoRequest request = new DoubaoRequest();
        request.setUrl(url);
        request.setBody(body);

        // 1. 加密 locinfo（如果提供了位置数据）
        if (locationData != null && !locationData.isEmpty()) {
            String locationJson = new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(locationData);
            String encryptedLocinfo = locationEncryptService.encryptLocationData(locationJson);
            request.setLocinfo(encryptedLocinfo);
        }

        // 2. 生成 Gorgon 签名族
        byte[] bodyBytes = body != null ? body.getBytes("UTF-8") : new byte[0];
        Map<String, String> gorgonHeaders = gorgonServiceWorker.getGorgon(url, bodyBytes).get();
        request.setGorgonHeaders(gorgonHeaders);

        // 3. 生成 AWS V4 签名
        String dateTime = getCurrentDateTime();
        Map<String, String> headers = new HashMap<>();
        headers.put("host", extractHost(url));
        headers.put("content-type", "application/json; charset=utf-8");
        headers.put("x-date", dateTime);

        String authHeader = signatureService.generateAuthorizationHeader(
            "POST",
            extractPath(url),
            extractQueryParams(url),
            headers,
            body,
            dateTime
        );
        request.setAuthorization(authHeader);

        // 4. 组装完整的请求头
        Map<String, String> completeHeaders = new HashMap<>();
        completeHeaders.putAll(gorgonHeaders);
        completeHeaders.put("Authorization", authHeader);
        completeHeaders.put("Content-Type", "application/json; charset=utf-8");
        completeHeaders.put("User-Agent", "Doubao/1.0");

        request.setHeaders(completeHeaders);

        return request;
    }

    /**
     * 快速生成签名（仅 Gorgon）
     */
    public Map<String, String> generateGorgonOnly(String url, String body) throws Exception {
        byte[] bodyBytes = body != null ? body.getBytes("UTF-8") : new byte[0];
        return gorgonServiceWorker.getGorgon(url, bodyBytes).get();
    }

    /**
     * 快速加密位置信息
     */
    public String encryptLocation(Map<String, Object> locationData) throws Exception {
        String locationJson = new com.fasterxml.jackson.databind.ObjectMapper()
            .writeValueAsString(locationData);
        return locationEncryptService.encryptLocationData(locationJson);
    }

    // 辅助方法
    private String getCurrentDateTime() {
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return sdf.format(new java.util.Date());
    }

    private String extractHost(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            return u.getHost();
        } catch (Exception e) {
            return "api.doubao.com";
        }
    }

    private String extractPath(String url) {
        try {
            java.net.URL u = new java.net.URL(url);
            String path = u.getPath();
            return path.isEmpty() ? "/" : path;
        } catch (Exception e) {
            return "/";
        }
    }

    private Map<String, String> extractQueryParams(String url) {
        Map<String, String> params = new HashMap<>();
        try {
            java.net.URL u = new java.net.URL(url);
            String query = u.getQuery();
            if (query != null && !query.isEmpty()) {
                for (String pair : query.split("&")) {
                    String[] kv = pair.split("=");
                    if (kv.length == 2) {
                        params.put(kv[0], kv[1]);
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return params;
    }

    /**
     * 豆包请求对象
     */
    public static class DoubaoRequest {
        private String url;
        private String body;
        private String locinfo;
        private Map<String, String> gorgonHeaders;
        private String authorization;
        private Map<String, String> headers;

        // Getters and Setters
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }

        public String getBody() { return body; }
        public void setBody(String body) { this.body = body; }

        public String getLocinfo() { return locinfo; }
        public void setLocinfo(String locinfo) { this.locinfo = locinfo; }

        public Map<String, String> getGorgonHeaders() { return gorgonHeaders; }
        public void setGorgonHeaders(Map<String, String> gorgonHeaders) {
            this.gorgonHeaders = gorgonHeaders;
        }

        public String getAuthorization() { return authorization; }
        public void setAuthorization(String authorization) {
            this.authorization = authorization;
        }

        public Map<String, String> getHeaders() { return headers; }
        public void setHeaders(Map<String, String> headers) { this.headers = headers; }

        /**
         * 生成 cURL 命令（用于测试）
         */
        public String toCurlCommand() {
            StringBuilder curl = new StringBuilder();
            curl.append("curl -X POST '").append(url).append("' \\\n");

            if (headers != null) {
                headers.forEach((key, value) -> {
                    curl.append("  -H '").append(key).append(": ").append(value).append("' \\\n");
                });
            }

            if (body != null) {
                curl.append("  -d '").append(body).append("'");
            }

            return curl.toString();
        }

        /**
         * 转为 Map（用于 JSON 输出）
         */
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("url", url);
            map.put("body", body);
            map.put("locinfo", locinfo);
            map.put("headers", headers);
            return map;
        }
    }
}
