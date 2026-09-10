package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;

/**
 * log.snssdk.com 响应解密服务
 *
 * 响应格式:
 * - [0-1]: Magic 0xac 0x00
 * - [2-3]: 头部长度 0x14 (20 bytes)
 * - [4-23]: 头部数据 (包含 nonce)
 * - [24+]: AES-CTR 加密的 Protobuf 数据
 *
 * 解密算法: AES-128-CTR
 * 密钥: 硬编码 (从二进制提取)
 * Nonce: response[4:12] (8 bytes)
 * Counter: 初始值 1
 */
@Service
public class AcResponseDecryptService {
    private static final Logger log = LoggerFactory.getLogger(AcResponseDecryptService.class);

    // 从二进制中提取的固定密钥 (偏移 0x6bbfe40)
    private static final byte[] AES_KEY = new byte[]{
            (byte) 0xe4, (byte) 0x03, (byte) 0x13, (byte) 0xaa,
            (byte) 0x00, (byte) 0x01, (byte) 0x3f, (byte) 0xd6,
            (byte) 0xf5, (byte) 0xfb, (byte) 0xff, (byte) 0xb5,
            (byte) 0xe1, (byte) 0x0a, (byte) 0x42, (byte) 0xa9
    };

    /**
     * 解密 ac 响应数据
     *
     * @param encrypted Base64 编码的加密响应
     * @return 解密后的 Protobuf 二进制数据
     */
    public byte[] decrypt(String encrypted) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encrypted);
        return decrypt(encryptedData);
    }

    /**
     * 解密 ac 响应数据
     *
     * @param encrypted 原始加密数据
     * @return 解密后的 Protobuf 二进制数据
     */
    public byte[] decrypt(byte[] encrypted) throws Exception {
        // 验证长度
        if (encrypted.length < 24) {
            throw new IllegalArgumentException("Invalid encrypted data: too short");
        }

        // 验证 magic bytes
        int magic = ((encrypted[0] & 0xFF) << 8) | (encrypted[1] & 0xFF);
        if (magic != 0xac00) {
            throw new IllegalArgumentException(
                    String.format("Invalid magic bytes: 0x%04x (expected 0xac00)", magic));
        }

        // 提取头部长度
        int headerLen = (encrypted[2] & 0xFF) | ((encrypted[3] & 0xFF) << 8);
        log.debug("AC response header length: {}", headerLen);

        // 提取 nonce (8 bytes from offset 4)
        byte[] nonce = Arrays.copyOfRange(encrypted, 4, 12);

        // 提取加密负载 (跳过 24 字节头部)
        byte[] payload = Arrays.copyOfRange(encrypted, 24, encrypted.length);

        log.debug("Decrypting AC response: payload size = {}", payload.length);

        // AES-CTR 解密
        byte[] decrypted = aesCtDecrypt(payload, AES_KEY, nonce, 1);

        log.info("AC response decrypted successfully: {} bytes", decrypted.length);

        return decrypted;
    }

    /**
     * AES-CTR 模式解密
     *
     * @param data         待解密数据
     * @param key          AES 密钥 (16 bytes)
     * @param nonce        Nonce (8 bytes)
     * @param counterInit  Counter 初始值
     * @return 解密后的数据
     */
    private byte[] aesCtDecrypt(byte[] data, byte[] key, byte[] nonce, long counterInit) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        // 构建 IV: nonce (8 bytes) + counter (8 bytes, big-endian)
        byte[] iv = new byte[16];
        System.arraycopy(nonce, 0, iv, 0, 8);

        // Counter 初始值 (big-endian, 8 bytes)
        ByteBuffer counterBuffer = ByteBuffer.allocate(8);
        counterBuffer.putLong(counterInit);
        System.arraycopy(counterBuffer.array(), 0, iv, 8, 8);

        // 使用 AES/CTR/NoPadding
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(data);
    }

    /**
     * 解密并转换为十六进制字符串 (用于调试)
     *
     * @param encrypted Base64 编码的加密响应
     * @return 十六进制字符串
     */
    public String decryptToHex(String encrypted) throws Exception {
        byte[] decrypted = decrypt(encrypted);
        StringBuilder sb = new StringBuilder();
        for (byte b : decrypted) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
