package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.TTTopSignatureService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

@RestController
@RequestMapping("/api/signature")
public class TTSignatureController {

    private static final Logger log = LoggerFactory.getLogger(TTSignatureController.class);

    @Autowired
    private TTTopSignatureService signatureService;

    /**
     * 生成 AWS V4 签名
     * POST /api/signature/generate
     *
     * 请求体:
     * {
     *   "method": "POST",
     *   "uri": "/api/endpoint",
     *   "queryParams": {},
     *   "headers": {
     *     "host": "api.example.com",
     *     "content-type": "application/json"
     *   },
     *   "payload": "{\"key\":\"value\"}",
     *   "dateTime": "20260809T025959Z"  // 可选，不提供则自动生成
     * }
     */
    @PostMapping("/generate")
    public Map<String, Object> generateSignature(@RequestBody Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String method = (String) request.getOrDefault("method", "POST");
            String uri = (String) request.getOrDefault("uri", "/");
            Map<String, String> queryParams = (Map<String, String>) request.getOrDefault("queryParams", new HashMap<>());
            Map<String, String> headers = (Map<String, String>) request.getOrDefault("headers", new HashMap<>());
            String payload = (String) request.getOrDefault("payload", "");

            // 生成或使用提供的时间戳
            String dateTime = (String) request.get("dateTime");
            if (dateTime == null) {
                dateTime = getCurrentDateTime();
            }

            log.info("生成签名请求 - method: {}, uri: {}", method, uri);

            long startTime = System.currentTimeMillis();
            String signature = signatureService.generateSignature(
                method, uri, queryParams, headers, payload, dateTime
            );
            long duration = System.currentTimeMillis() - startTime;

            // 同时生成授权头
            String authHeader = signatureService.generateAuthorizationHeader(
                method, uri, queryParams, headers, payload, dateTime
            );

            result.put("success", true);
            result.put("signature", signature);
            result.put("authorization", authHeader);
            result.put("dateTime", dateTime);
            result.put("duration_ms", duration);

            log.info("签名生成成功，耗时 {} ms", duration);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("签名生成失败", e);
        }

        return result;
    }

    /**
     * 生成授权头
     * POST /api/signature/authorization
     */
    @PostMapping("/authorization")
    public Map<String, Object> generateAuthorization(@RequestBody Map<String, Object> request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String method = (String) request.getOrDefault("method", "POST");
            String uri = (String) request.getOrDefault("uri", "/");
            Map<String, String> queryParams = (Map<String, String>) request.getOrDefault("queryParams", new HashMap<>());
            Map<String, String> headers = (Map<String, String>) request.getOrDefault("headers", new HashMap<>());
            String payload = (String) request.getOrDefault("payload", "");

            String dateTime = (String) request.get("dateTime");
            if (dateTime == null) {
                dateTime = getCurrentDateTime();
            }

            log.info("生成授权头请求 - method: {}, uri: {}", method, uri);

            long startTime = System.currentTimeMillis();
            String authHeader = signatureService.generateAuthorizationHeader(
                method, uri, queryParams, headers, payload, dateTime
            );
            long duration = System.currentTimeMillis() - startTime;

            result.put("success", true);
            result.put("authorization", authHeader);
            result.put("dateTime", dateTime);
            result.put("duration_ms", duration);

            log.info("授权头生成成功，耗时 {} ms", duration);

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("授权头生成失败", e);
        }

        return result;
    }

    /**
     * 配置签名密钥
     * POST /api/signature/config
     *
     * 请求体:
     * {
     *   "accessKey": "AKIAIOSFODNN7EXAMPLE",
     *   "secretKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
     * }
     */
    @PostMapping("/config")
    public Map<String, Object> configureKeys(@RequestBody Map<String, String> request) {
        Map<String, Object> result = new HashMap<>();

        try {
            String accessKey = request.get("accessKey");
            String secretKey = request.get("secretKey");

            if (accessKey != null) {
                signatureService.setAccessKey(accessKey);
            }
            if (secretKey != null) {
                signatureService.setSecretKey(secretKey);
            }

            result.put("success", true);
            result.put("message", "密钥配置成功");

            log.info("签名密钥配置已更新");

        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("密钥配置失败", e);
        }

        return result;
    }

    /**
     * 健康检查
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("service", "TTTopSignatureService");
        result.put("status", "running");
        result.put("algorithm", "AWS Signature V4");
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }

    /**
     * 获取当前 ISO 8601 格式的时间戳
     * 格式: 20260809T025959Z
     */
    private String getCurrentDateTime() {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date());
    }
}
