package com.anjia.unidbgserver.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class LocationEncryptService {

    private static final byte XOR_KEY = (byte) 0x9d;

    /**
     * 加密位置数据
     * 算法：单字节 XOR (key=0x9d) + Base64 编码
     *
     * @param jsonData JSON 格式的位置信息
     * @return 加密后的 Base64 字符串
     */
    public String encryptLocationData(String jsonData) {
        // 1. 将 JSON 字符串转为字节数组
        byte[] plaintext = jsonData.getBytes(StandardCharsets.UTF_8);

        // 2. 单字节 XOR 加密
        byte[] encrypted = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++) {
            encrypted[i] = (byte) (plaintext[i] ^ XOR_KEY);
        }

        // 3. Base64 编码
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * 解密位置数据（用于测试验证）
     *
     * @param encryptedBase64 加密后的 Base64 字符串
     * @return 解密后的 JSON 字符串
     */
    public String decryptLocationData(String encryptedBase64) {
        // 1. Base64 解码
        byte[] encrypted = Base64.getDecoder().decode(encryptedBase64);

        // 2. 单字节 XOR 解密
        byte[] plaintext = new byte[encrypted.length];
        for (int i = 0; i < encrypted.length; i++) {
            plaintext[i] = (byte) (encrypted[i] ^ XOR_KEY);
        }

        // 3. 转为字符串
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * 将字典数据转换为 Base64 编码（对应 BDLEncryptUtil.base64StringWithDictionary）
     * @param jsonData JSON 格式的数据
     * @return Base64 编码的字符串
     */
    public String base64StringWithDictionary(String jsonData) {
        return encryptLocationData(jsonData);
    }
}
