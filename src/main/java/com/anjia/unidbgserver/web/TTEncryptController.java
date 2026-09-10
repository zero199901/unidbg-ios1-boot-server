package com.anjia.unidbgserver.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.service.TTEncryptServiceWorker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequestMapping(path = "/api/tt-encrypt", produces = MediaType.APPLICATION_JSON_VALUE)
public class TTEncryptController {
    private static final Logger log = LoggerFactory.getLogger(TTEncryptController.class);


    @Resource(name = "ttEncryptWorker")
    private TTEncryptServiceWorker ttEncryptServiceWorker;

    @Resource
    private com.anjia.unidbgserver.service.AcResponseDecryptService acResponseDecryptService;

    /**
     * POST /api/tt-encrypt/encrypt
     * body: 待签名的原始请求体（字符串或 JSON）
     * 返回: Base64 编码的签名结果
     */
    @PostMapping(value = "encrypt", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String encrypt(@RequestBody(required = false) String body) throws Exception {
        byte[] result = ttEncryptServiceWorker.ttEncrypt(null, body).get();
        String encoded = Base64.getEncoder().encodeToString(result);
        log.info("encrypt body.len={}, result.len={}", body != null ? body.length() : 0, result.length);
        return encoded;
    }

    /**
     * GET /api/tt-encrypt/encrypt?body=xxx  （快速测试用）
     */
    @GetMapping(value = "encrypt")
    public String encryptGet(@RequestParam(required = false, defaultValue = "") String body) throws Exception {
        byte[] result = ttEncryptServiceWorker.ttEncrypt(null, body).get();
        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * POST /api/tt-encrypt/decrypt
     * body: Base64 编码的加密数据（即 encrypt 接口的输出）
     * 返回: 原始明文字符串
     */
    @PostMapping(value = "decrypt", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String decrypt(@RequestBody String body) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(body.trim());
        byte[] plaintext = ttEncryptServiceWorker.ttDecrypt(encrypted).get();
        log.info("decrypt encrypted.len={}, plaintext.len={}", encrypted.length, plaintext.length);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * POST /api/tt-encrypt/tc-decrypt
     * body: Base64 编码的 tc 协议加密数据（来自 HAR 文件）
     * 返回: 解压后的明文字符串
     *
     * tc 协议格式: [2字节 "tc"] + [2字节版本] + [4字节元数据] + [bvx2 压缩数据]
     * 使用 Apple libcompression.dylib 进行解压
     */
    @PostMapping(value = "tc-decrypt", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String tcDecrypt(@RequestBody String body) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(body.trim());
        byte[] plaintext = ttEncryptServiceWorker.tcDecrypt(encrypted).get();
        log.info("tc-decrypt encrypted.len={}, plaintext.len={}", encrypted.length, plaintext.length);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * GET /api/tt-encrypt/tc-decrypt?body=xxx  （快速测试用）
     */
    @GetMapping(value = "tc-decrypt")
    public String tcDecryptGet(@RequestParam(required = false, defaultValue = "") String body) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(body.trim());
        byte[] plaintext = ttEncryptServiceWorker.tcDecrypt(encrypted).get();
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * POST /api/tt-encrypt/ac-response-decrypt
     * body: Base64 编码的 ac 响应数据
     * 返回: 解密后的 Protobuf 二进制数据（十六进制字符串）
     *
     * ac 响应格式:
     * - Magic: 0xac 0x00
     * - 算法: AES-128-CTR
     * - 结果: Protobuf 二进制数据
     */
    @PostMapping(value = "ac-response-decrypt", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String acResponseDecrypt(@RequestBody String body) throws Exception {
        String base64Data = body.trim();
        log.info("ac-response-decrypt request, base64 length={}", base64Data.length());

        byte[] decrypted = acResponseDecryptService.decrypt(base64Data);

        log.info("ac-response-decrypt success, decrypted length={}", decrypted.length);

        // 返回十六进制格式，便于查看
        return acResponseDecryptService.decryptToHex(base64Data);
    }

    /**
     * GET /api/tt-encrypt/ac-response-decrypt?body=xxx  （快速测试用）
     */
    @GetMapping(value = "ac-response-decrypt")
    public String acResponseDecryptGet(@RequestParam(required = false, defaultValue = "") String body) throws Exception {
        return acResponseDecrypt(body);
    }

    /**
     * POST /api/tt-encrypt/bvx2-decompress
     * body: Base64 编码的 bvx2 压缩数据
     * 返回: 解压后的原始数据（Base64 编码）
     */
    @PostMapping(value = "bvx2-decompress", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String bvx2Decompress(@RequestBody String body) throws Exception {
        byte[] compressed = Base64.getDecoder().decode(body.trim());
        byte[] decompressed = ttEncryptServiceWorker.decompressBVX2(compressed).get();
        log.info("bvx2-decompress compressed.len={}, decompressed.len={}", compressed.length, decompressed.length);
        return Base64.getEncoder().encodeToString(decompressed);
    }

    /**
     * GET /api/tt-encrypt/bvx2-decompress?body=xxx  （快速测试用）
     */
    @GetMapping(value = "bvx2-decompress")
    public String bvx2DecompressGet(@RequestParam(required = false, defaultValue = "") String body) throws Exception {
        return bvx2Decompress(body);
    }
}
