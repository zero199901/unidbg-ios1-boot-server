package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.CRC32;

/**
 * ByteDance Gorgon 纯 Java 实现
 *
 * 基于公开的 Gorgon v4 算法逆向分析
 * 注意：这是简化版本，真实算法可能有额外的混淆和参数
 */
public class GorgonAlgorithm {
    private static final Logger log = LoggerFactory.getLogger(GorgonAlgorithm.class);


    /**
     * 生成 Gorgon 签名
     *
     * @param url 完整 URL（含 query 参数）
     * @param body 请求体字节数组
     * @return Map 包含 x-gorgon, x-khronos, x-ladon
     */
    public static Map<String, String> generate(String url, byte[] body) {
        long khronos = System.currentTimeMillis() / 1000;

        try {
            // 1. 提取 URL 路径和 query
            String path = extractPath(url);
            String query = extractQuery(url);

            // 2. 构造待签名数据
            // 格式：path + query + body + khronos
            byte[] pathBytes = path.getBytes(StandardCharsets.UTF_8);
            byte[] queryBytes = query != null ? query.getBytes(StandardCharsets.UTF_8) : new byte[0];
            byte[] khronosBytes = String.valueOf(khronos).getBytes(StandardCharsets.UTF_8);

            byte[] signData = concat(pathBytes, queryBytes, body, khronosBytes);

            // 3. 计算 Gorgon（多轮哈希 + CRC32）
            String gorgon = calculateGorgon(signData, khronos);

            // 4. 计算 Ladon（备用签名）
            String ladon = calculateLadon(signData);

            // 5. 计算 Argus（复杂签名，暂用简化版）
            String argus = calculateArgus(signData, url);

            // 6. 计算 Medusa（超大签名，暂用简化版）
            String medusa = calculateMedusa(signData, url);

            // 7. 计算 SS-Stub（设备指纹）
            String ssStub = calculateSsStub(signData);

            Map<String, String> result = new HashMap<>();
            result.put("x-gorgon", gorgon);
            result.put("x-khronos", String.valueOf(khronos));
            result.put("x-ladon", ladon);
            result.put("x-argus", argus);
            result.put("x-medusa", medusa);
            result.put("x-ss-stub", ssStub);

            log.info("✓ 完整签名已生成: 6个参数");

            return result;

        } catch (Exception e) {
            log.error("Gorgon 生成失败: {}", e.getMessage(), e);
            return getFallbackGorgon(khronos);
        }
    }

    /**
     * 计算 Gorgon 主签名
     *
     * 真实 Gorgon v4 格式（基于抓包分析）：
     * [4字节版本头] + [4字节时间戳] + [16字节MD5哈希] + [2字节校验码]
     * 总共 26 字节 = 52 个十六进制字符
     */
    private static String calculateGorgon(byte[] data, long khronos) throws Exception {
        // 版本头（观察到的值：84048064, 8404c05c, 84046060 等）
        // 前4位固定为 8404，后4位可能与请求类型/设备相关
        int version = 0x84048064;  // 使用观察到的最常见值

        // MD5 哈希
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hash = md5.digest(data);

        // CRC32 校验（取低16位）
        CRC32 crc = new CRC32();
        crc.update(data);
        int crcValue = (int) (crc.getValue() & 0xFFFF);

        // 组装：版本(8位) + 时间戳(8位) + MD5(32位) + CRC16(4位) = 52位
        StringBuilder sb = new StringBuilder();

        // 版本（8位16进制）
        sb.append(String.format("%08x", version));

        // 时间戳（8位16进制）
        // 真实值：x-khronos=1786099533 → gorgon时间戳=0000e98e (59790)
        // 可能取的是时间戳的某个片段，这里先用低16位
        sb.append(String.format("%08x", (int)(khronos & 0xFFFF)));

        // MD5 哈希（32位16进制 = 16字节）
        for (int i = 0; i < 16; i++) {
            sb.append(String.format("%02x", hash[i] & 0xff));
        }

        // CRC16 校验（4位16进制 = 2字节）
        sb.append(String.format("%04x", crcValue));

        return sb.toString();
    }

    /**
     * 计算 Ladon 备用签名
     * Ladon 是 Base64 编码的 SHA1
     */
    private static String calculateLadon(byte[] data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] hash = sha1.digest(data);
        return java.util.Base64.getEncoder().encodeToString(hash);
    }

    /**
     * 计算 Argus 签名（简化版）
     * 真实 Argus: 216字符 Base64，需要调用原生库
     * 这里用 SHA-256 + 填充模拟
     */
    private static String calculateArgus(byte[] data, String url) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(concat(data, url.getBytes(StandardCharsets.UTF_8)));

        // 扩展到约162字节（Base64后216字符）
        byte[] extended = new byte[162];
        for (int i = 0; i < extended.length; i++) {
            extended[i] = hash[i % hash.length];
        }

        return java.util.Base64.getEncoder().encodeToString(extended);
    }

    /**
     * 计算 Medusa 签名（简化版）
     * 真实 Medusa: 828字符 Base64，需要调用原生库
     * 这里用 SHA-512 + 填充模拟
     */
    private static String calculateMedusa(byte[] data, String url) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha512.digest(concat(data, url.getBytes(StandardCharsets.UTF_8)));

        // 扩展到约621字节（Base64后828字符）
        byte[] extended = new byte[621];
        for (int i = 0; i < extended.length; i++) {
            extended[i] = hash[i % hash.length];
        }

        return java.util.Base64.getEncoder().encodeToString(extended);
    }

    /**
     * 计算 SS-Stub（设备指纹）
     * 32字符十六进制 = 16字节 MD5
     */
    private static String calculateSsStub(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hash = md5.digest(data);

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    private static String extractPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) {
                url = url.substring(schemeEnd + 3);
            }
            int hostEnd = url.indexOf('/');
            if (hostEnd != -1) {
                url = url.substring(hostEnd);
            }
            int queryStart = url.indexOf('?');
            if (queryStart != -1) {
                return url.substring(0, queryStart);
            }
            return url;
        } catch (Exception e) {
            return "/";
        }
    }

    private static String extractQuery(String url) {
        int queryStart = url.indexOf('?');
        if (queryStart != -1 && queryStart < url.length() - 1) {
            return url.substring(queryStart + 1);
        }
        return "";
    }

    private static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length;
        }
        byte[] result = new byte[totalLength];
        int pos = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, pos, arr.length);
            pos += arr.length;
        }
        return result;
    }

    private static Map<String, String> getFallbackGorgon(long khronos) {
        Map<String, String> result = new HashMap<>();
        result.put("x-gorgon", "0404806400000000ffffffffffffffffffffffffffffffff");
        result.put("x-khronos", String.valueOf(khronos));
        result.put("x-ladon", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        result.put("x-argus", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        result.put("x-medusa", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        result.put("x-ss-stub", "00000000000000000000000000000000");
        log.warn("⚠ 使用 fallback 签名");
        return result;
    }
}
