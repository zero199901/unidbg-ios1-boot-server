package com.anjia.unidbgserver.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 端到端集成测试
 * 验证所有加密字段协同工作
 */
@SpringBootTest
public class EndToEndIntegrationTest {

    @Autowired
    private LocationEncryptService locationEncryptService;

    @Autowired
    private TTTopSignatureService signatureService;

    @Autowired
    private GorgonServiceWorker gorgonServiceWorker;

    /**
     * 测试场景：模拟完整的豆包聊天请求
     */
    @Test
    public void testCompleteChatRequest() throws Exception {
        System.out.println("\n" + "=".repeat(60));
        System.out.println("端到端集成测试：模拟豆包聊天请求");
        System.out.println("=".repeat(60) + "\n");

        // 1. 准备请求数据
        String apiUrl = "https://api.doubao.com/v1/chat/send";
        String queryParams = "?conversation_id=123&user_id=456";
        String fullUrl = apiUrl + queryParams;

        // 2. 构建请求体
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("message", "你好，豆包！");
        requestBody.put("conversation_id", "123");

        // 添加 locinfo（加密的位置信息）
        Map<String, Object> locationData = new HashMap<>();
        Map<String, Object> status = new HashMap<>();
        status.put("restricted_mode", 2);
        status.put("permission", 30);
        status.put("is_bluetooth_open", true);
        status.put("system_region", "CN");
        status.put("system_language", "zh-Hans-CN");
        status.put("location_mode", 16);
        status.put("device_type", 1);
        locationData.put("status", status);

        Map<String, String> regionInfo = new HashMap<>();
        regionInfo.put("locale", "zh-CN");
        regionInfo.put("system_language", "zh");
        regionInfo.put("system_region", "CN");
        locationData.put("region_info", regionInfo);
        locationData.put("timestamp", System.currentTimeMillis() / 1000);
        locationData.put("upload_source", "bdlocation_boot_upload_device_info");

        String locationJson = new com.fasterxml.jackson.databind.ObjectMapper()
            .writeValueAsString(locationData);

        // 加密 locinfo
        String encryptedLocinfo = locationEncryptService.encryptLocationData(locationJson);
        requestBody.put("locinfo", encryptedLocinfo);

        // 转换请求体为 JSON
        String bodyJson = new com.fasterxml.jackson.databind.ObjectMapper()
            .writeValueAsString(requestBody);

        System.out.println("1. 请求 URL:");
        System.out.println("   " + fullUrl);
        System.out.println("\n2. 请求体:");
        System.out.println("   " + bodyJson.substring(0, Math.min(100, bodyJson.length())) + "...");

        // 3. 生成 Gorgon 签名族
        byte[] bodyBytes = bodyJson.getBytes("UTF-8");
        Map<String, String> gorgonHeaders = gorgonServiceWorker.getGorgon(fullUrl, bodyBytes).get();

        System.out.println("\n3. Gorgon 签名族:");
        gorgonHeaders.forEach((key, value) -> {
            String displayValue = value.length() > 50 ? value.substring(0, 50) + "..." : value;
            System.out.println("   " + key + ": " + displayValue);
        });

        // 验证 Gorgon 签名
        assertNotNull(gorgonHeaders.get("x-gorgon"), "x-gorgon 不能为空");
        assertNotNull(gorgonHeaders.get("x-khronos"), "x-khronos 不能为空");
        assertNotNull(gorgonHeaders.get("x-ladon"), "x-ladon 不能为空");
        assertNotNull(gorgonHeaders.get("x-argus"), "x-argus 不能为空");
        assertNotNull(gorgonHeaders.get("x-medusa"), "x-medusa 不能为空");
        assertNotNull(gorgonHeaders.get("x-ss-stub"), "x-ss-stub 不能为空");
        assertNotNull(gorgonHeaders.get("x-helios"), "x-helios 不能为空");

        // 4. 生成 AWS V4 签名
        Map<String, String> requestHeaders = new HashMap<>();
        requestHeaders.put("host", "api.doubao.com");
        requestHeaders.put("content-type", "application/json; charset=utf-8");
        requestHeaders.put("x-date", getCurrentDateTime());

        String dateTime = getCurrentDateTime();
        String awsSignature = signatureService.generateSignature(
            "POST",
            "/v1/chat/send",
            parseQueryParams(queryParams),
            requestHeaders,
            bodyJson,
            dateTime
        );

        String authHeader = signatureService.generateAuthorizationHeader(
            "POST",
            "/v1/chat/send",
            parseQueryParams(queryParams),
            requestHeaders,
            bodyJson,
            dateTime
        );

        System.out.println("\n4. AWS V4 签名:");
        System.out.println("   Signature: " + awsSignature.substring(0, Math.min(50, awsSignature.length())) + "...");
        System.out.println("   Authorization: " + authHeader.substring(0, Math.min(80, authHeader.length())) + "...");

        assertNotNull(awsSignature, "AWS 签名不能为空");
        assertEquals(64, awsSignature.length(), "AWS 签名长度应为64");

        // 5. 组装完整的 HTTP 请求头
        System.out.println("\n5. 完整请求头:");
        Map<String, String> completeHeaders = new HashMap<>();
        completeHeaders.putAll(gorgonHeaders);
        completeHeaders.put("Authorization", authHeader);
        completeHeaders.put("Content-Type", "application/json; charset=utf-8");
        completeHeaders.put("User-Agent", "Doubao/1.0");

        completeHeaders.forEach((key, value) -> {
            String displayValue = value.length() > 60 ? value.substring(0, 60) + "..." : value;
            System.out.println("   " + key + ": " + displayValue);
        });

        // 6. 输出 cURL 命令（用于实际测试）
        System.out.println("\n6. cURL 测试命令:");
        System.out.println("   curl -X POST '" + fullUrl + "' \\");
        completeHeaders.forEach((key, value) -> {
            System.out.println("     -H '" + key + ": " + value + "' \\");
        });
        System.out.println("     -d '" + bodyJson + "'");

        System.out.println("\n" + "=".repeat(60));
        System.out.println("✅ 端到端集成测试通过！");
        System.out.println("所有加密字段已成功生成并验证");
        System.out.println("=".repeat(60) + "\n");
    }

    /**
     * 测试场景：批量签名性能测试
     */
    @Test
    public void testBatchSigningPerformance() throws Exception {
        System.out.println("\n性能测试：批量签名");

        int iterations = 100;
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < iterations; i++) {
            String url = "https://api.doubao.com/test?id=" + i;
            String body = "{\"message\":\"test" + i + "\"}";

            // 生成 Gorgon 签名
            gorgonServiceWorker.getGorgon(url, body.getBytes()).get();

            // 生成 locinfo 加密
            locationEncryptService.encryptLocationData(body);
        }

        long duration = System.currentTimeMillis() - startTime;
        double avgTime = duration / (double) iterations;

        System.out.println("  迭代次数: " + iterations);
        System.out.println("  总耗时: " + duration + " ms");
        System.out.println("  平均耗时: " + String.format("%.2f", avgTime) + " ms/次");
        System.out.println("  吞吐量: " + String.format("%.0f", 1000.0 / avgTime) + " ops/s");

        assertTrue(avgTime < 50, "平均耗时应小于 50ms");
    }

    /**
     * 测试场景：加密字段往返验证
     */
    @Test
    public void testEncryptionRoundTrip() {
        System.out.println("\n往返测试：加密->解密");

        String originalData = "{\"test\":\"数据\",\"value\":123}";

        // 加密
        String encrypted = locationEncryptService.encryptLocationData(originalData);
        assertNotNull(encrypted, "加密结果不能为空");
        System.out.println("  原始数据: " + originalData);
        System.out.println("  加密后: " + encrypted.substring(0, Math.min(50, encrypted.length())) + "...");

        // 解密
        String decrypted = locationEncryptService.decryptLocationData(encrypted);
        System.out.println("  解密后: " + decrypted);

        // 验证
        assertEquals(originalData, decrypted, "解密后应与原始数据一致");
        System.out.println("  ✅ 往返验证通过");
    }

    // 辅助方法
    private String getCurrentDateTime() {
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        return sdf.format(new java.util.Date());
    }

    private Map<String, String> parseQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty() || query.equals("?")) {
            return params;
        }

        String cleanQuery = query.startsWith("?") ? query.substring(1) : query;
        for (String pair : cleanQuery.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                params.put(kv[0], kv[1]);
            }
        }
        return params;
    }
}
