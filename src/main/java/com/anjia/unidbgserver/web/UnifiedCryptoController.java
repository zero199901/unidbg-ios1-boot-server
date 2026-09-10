package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.UnifiedCryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * 统一加密 API 控制器
 * 提供一站式加密服务接口
 */
@RestController
@RequestMapping("/api/unified")
public class UnifiedCryptoController {

    private static final Logger log = LoggerFactory.getLogger(UnifiedCryptoController.class);

    @Autowired
    private UnifiedCryptoService unifiedCryptoService;

    /**
     * 生成完整的豆包请求
     * POST /api/unified/request
     *
     * 请求体:
     * {
     *   "url": "https://api.doubao.com/v1/chat/send?conversation_id=123",
     *   "body": "{\"message\":\"你好\"}",
     *   "locationData": {
     *     "status": {"restricted_mode": 2, "permission": 30},
     *     "timestamp": 1786215133
     *   }
     * }
     *
     * 响应:
     * {
     *   "success": true,
     *   "request": {
     *     "url": "...",
     *     "body": "...",
     *     "locinfo": "...",
     *     "headers": {
     *       "x-gorgon": "...",
     *       "Authorization": "...",
     *       ...
     *     }
     *   },
     *   "curlCommand": "curl -X POST ...",
     *   "duration_ms": 15
     * }
     */
    @PostMapping("/request")
    public Map<String, Object> generateCompleteRequest(@RequestBody Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String url = (String) request.get("url");
            String body = (String) request.get("body");
            Map<String, Object> locationData = (Map<String, Object>) request.get("locationData");

            if (url == null || url.isEmpty()) {
                result.put("success", false);
                result.put("error", "URL 不能为空");
                return result;
            }

            log.info("生成完整请求 - URL: {}", url);

            long startTime = System.currentTimeMillis();
            UnifiedCryptoService.DoubaoRequest doubaoRequest =
                unifiedCryptoService.generateCompleteRequest(url, body, locationData);
            long duration = System.currentTimeMillis() - startTime;

            result.put("success", true);
            result.put("request", doubaoRequest.toMap());
            result.put("curlCommand", doubaoRequest.toCurlCommand());
            result.put("duration_ms", duration);

            log.info("请求生成成功，耗时 {} ms", duration);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("请求生成失败", e);
        }

        return result;
    }

    /**
     * 快速生成 Gorgon 签名
     * POST /api/unified/gorgon
     *
     * 请求体:
     * {
     *   "url": "https://api.doubao.com/endpoint",
     *   "body": "{\"key\":\"value\"}"
     * }
     */
    @PostMapping("/gorgon")
    public Map<String, Object> generateGorgonOnly(@RequestBody Map<String, String> request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String url = request.get("url");
            String body = request.getOrDefault("body", "");

            log.info("生成 Gorgon 签名 - URL: {}", url);

            long startTime = System.currentTimeMillis();
            Map<String, String> gorgonHeaders = unifiedCryptoService.generateGorgonOnly(url, body);
            long duration = System.currentTimeMillis() - startTime;

            result.put("success", true);
            result.put("headers", gorgonHeaders);
            result.put("duration_ms", duration);

            log.info("Gorgon 签名生成成功，耗时 {} ms", duration);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("Gorgon 签名生成失败", e);
        }

        return result;
    }

    /**
     * 快速加密位置信息
     * POST /api/unified/location
     *
     * 请求体:
     * {
     *   "status": {"restricted_mode": 2, "permission": 30},
     *   "timestamp": 1786215133
     * }
     */
    @PostMapping("/location")
    public Map<String, Object> encryptLocation(@RequestBody Map<String, Object> locationData) {
        Map<String, Object> result = new HashMap<>();

        try {
            log.info("加密位置信息");

            long startTime = System.currentTimeMillis();
            String encrypted = unifiedCryptoService.encryptLocation(locationData);
            long duration = System.currentTimeMillis() - startTime;

            result.put("success", true);
            result.put("locinfo", encrypted);
            result.put("duration_ms", duration);

            log.info("位置信息加密成功，耗时 {} ms", duration);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("位置信息加密失败", e);
        }

        return result;
    }

    /**
     * 健康检查
     * GET /api/unified/health
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("service", "UnifiedCryptoService");
        result.put("status", "running");
        result.put("features", new String[]{
            "locinfo 加密",
            "Gorgon 签名族 (7个字段)",
            "AWS V4 签名",
            "完整请求生成"
        });
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }

    /**
     * 服务统计
     * GET /api/unified/stats
     */
    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Map<String, Object> result = new HashMap<>();

        Map<String, String> algorithms = new HashMap<>();
        algorithms.put("locinfo", "XOR 0x9d + Base64");
        algorithms.put("x-gorgon", "MD5 + CRC16 + 版本号");
        algorithms.put("x-khronos", "Unix 时间戳");
        algorithms.put("x-ladon", "SHA-1 Base64");
        algorithms.put("x-argus", "AES-128-CBC (162字节)");
        algorithms.put("x-medusa", "固定模板加密 (621字节)");
        algorithms.put("x-ss-stub", "MD5 大写");
        algorithms.put("x-helios", "SHA-256 混合 (36字节)");
        algorithms.put("TTTopSignature", "AWS Signature V4");

        result.put("algorithms", algorithms);
        result.put("totalFields", 9);
        result.put("verified", 8);
        result.put("pending", 1);

        return result;
    }

    /**
     * 使用示例
     * GET /api/unified/example
     */
    @GetMapping("/example")
    public Map<String, Object> example() {
        Map<String, Object> result = new HashMap<>();

        try {
            // 示例请求
            Map<String, Object> exampleRequest = new HashMap<>();
            exampleRequest.put("url", "https://api.doubao.com/v1/chat/send?conversation_id=123");
            exampleRequest.put("body", "{\"message\":\"你好，豆包！\"}");

            Map<String, Object> locationData = new HashMap<>();
            Map<String, Object> status = new HashMap<>();
            status.put("restricted_mode", 2);
            status.put("permission", 30);
            status.put("is_bluetooth_open", true);
            status.put("system_region", "CN");
            locationData.put("status", status);
            locationData.put("timestamp", System.currentTimeMillis() / 1000);

            exampleRequest.put("locationData", locationData);

            result.put("endpoint", "POST /api/unified/request");
            result.put("example_request", exampleRequest);
            result.put("description", "生成完整的豆包请求，包含所有加密字段和签名");

            // cURL 示例
            String exampleJson = new com.fasterxml.jackson.databind.ObjectMapper()
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(exampleRequest);

            String curlExample = "curl -X POST http://localhost:8090/api/unified/request \\\n" +
                "  -H \"Content-Type: application/json\" \\\n" +
                "  -d '" + exampleJson.replace("\n", "\n      ") + "'";

            result.put("curl_example", curlExample);

        } catch (Exception e) {
            result.put("error", e.getMessage());
        }

        return result;
    }
}
