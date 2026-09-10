package com.anjia.unidbgserver.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

public class TTTopSignatureServiceTest {

    @Test
    public void testAWSSignatureV4() {
        TTTopSignatureService service = new TTTopSignatureService();

        // 使用 AWS 官方测试用例
        service.setAccessKey("AKIDEXAMPLE");
        service.setSecretKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

        String method = "POST";
        String uri = "/";
        Map<String, String> queryParams = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        headers.put("host", "example.amazonaws.com");
        headers.put("content-type", "application/x-www-form-urlencoded");
        String payload = "Action=ListUsers&Version=2010-05-08";
        String dateTime = "20150830T123600Z";

        String signature = service.generateSignature(method, uri, queryParams, headers, payload, dateTime);

        assertNotNull(signature);
        System.out.println("签名: " + signature);

        // 生成授权头
        String authHeader = service.generateAuthorizationHeader(method, uri, queryParams, headers, payload, dateTime);
        assertNotNull(authHeader);
        System.out.println("授权头: " + authHeader);

        assertTrue(authHeader.startsWith("AWS4-HMAC-SHA256"));
        assertTrue(authHeader.contains("Credential="));
        assertTrue(authHeader.contains("SignedHeaders="));
        assertTrue(authHeader.contains("Signature="));
    }

    @Test
    public void testGetRequest() {
        TTTopSignatureService service = new TTTopSignatureService();

        String method = "GET";
        String uri = "/api/endpoint";
        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("param1", "value1");
        queryParams.put("param2", "value2");

        Map<String, String> headers = new HashMap<>();
        headers.put("host", "api.example.com");

        String payload = "";
        String dateTime = "20260809T030000Z";

        String signature = service.generateSignature(method, uri, queryParams, headers, payload, dateTime);

        assertNotNull(signature);
        assertEquals(64, signature.length()); // SHA-256 哈希的十六进制长度
        System.out.println("GET 请求签名: " + signature);
    }

    @Test
    public void testPostWithJsonPayload() {
        TTTopSignatureService service = new TTTopSignatureService();

        String method = "POST";
        String uri = "/api/doubao/chat";
        Map<String, String> queryParams = new HashMap<>();

        Map<String, String> headers = new HashMap<>();
        headers.put("host", "api.doubao.com");
        headers.put("content-type", "application/json");
        headers.put("x-date", "20260809T030000Z");

        String payload = "{\"message\":\"你好\",\"conversation_id\":\"123\"}";
        String dateTime = "20260809T030000Z";

        String signature = service.generateSignature(method, uri, queryParams, headers, payload, dateTime);

        assertNotNull(signature);
        System.out.println("豆包请求签名: " + signature);

        String authHeader = service.generateAuthorizationHeader(method, uri, queryParams, headers, payload, dateTime);
        System.out.println("豆包授权头: " + authHeader);
    }

    @Test
    public void testEmptyPayload() {
        TTTopSignatureService service = new TTTopSignatureService();

        String method = "GET";
        String uri = "/";
        Map<String, String> queryParams = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        headers.put("host", "example.com");

        String payload = "";
        String dateTime = "20260809T030000Z";

        String signature = service.generateSignature(method, uri, queryParams, headers, payload, dateTime);

        assertNotNull(signature);
        assertEquals(64, signature.length());
        System.out.println("空载荷签名: " + signature);
    }

    @Test
    public void testChineseCharacters() {
        TTTopSignatureService service = new TTTopSignatureService();

        String method = "POST";
        String uri = "/api/chat";
        Map<String, String> queryParams = new HashMap<>();

        Map<String, String> headers = new HashMap<>();
        headers.put("host", "api.doubao.com");
        headers.put("content-type", "application/json; charset=utf-8");

        String payload = "{\"message\":\"你好，豆包！\",\"user_id\":\"测试用户\"}";
        String dateTime = "20260809T030000Z";

        String signature = service.generateSignature(method, uri, queryParams, headers, payload, dateTime);

        assertNotNull(signature);
        assertEquals(64, signature.length());
        System.out.println("中文字符签名: " + signature);
    }
}
