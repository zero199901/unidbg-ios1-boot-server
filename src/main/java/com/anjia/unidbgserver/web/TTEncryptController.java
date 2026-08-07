package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.TTEncryptServiceWorker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Base64;

@Slf4j
@RestController
@RequestMapping(path = "/api/tt-encrypt", produces = MediaType.APPLICATION_JSON_VALUE)
public class TTEncryptController {

    @Resource(name = "ttEncryptWorker")
    private TTEncryptServiceWorker ttEncryptServiceWorker;

    /**
     * POST /api/tt-encrypt/encrypt
     * body: 待签名的原始请求体（字符串或 JSON）
     * 返回: Base64 编码的签名结果
     */
    @SneakyThrows
    @PostMapping(value = "encrypt", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String encrypt(@RequestBody(required = false) String body) {
        byte[] result = ttEncryptServiceWorker.ttEncrypt(null, body).get();
        String encoded = Base64.getEncoder().encodeToString(result);
        log.info("encrypt body.len={}, result.len={}", body != null ? body.length() : 0, result.length);
        return encoded;
    }

    /**
     * GET /api/tt-encrypt/encrypt?body=xxx  （快速测试用）
     */
    @SneakyThrows
    @GetMapping(value = "encrypt")
    public String encryptGet(@RequestParam(required = false, defaultValue = "") String body) {
        byte[] result = ttEncryptServiceWorker.ttEncrypt(null, body).get();
        return Base64.getEncoder().encodeToString(result);
    }
}
