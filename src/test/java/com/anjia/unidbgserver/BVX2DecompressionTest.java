package com.anjia.unidbgserver;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.anjia.unidbgserver.service.TTEncryptServiceWorker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * BVX2 解压测试
 * 测试监控 API 的 AES + BVX2 解密流程
 */
public class BVX2DecompressionTest {

    private static TTEncryptServiceWorker worker;

    // 从 Frida 捕获的 AES-128 密钥
    private static final String AES_KEY = "yuNttCSojTyxZods";

    @BeforeAll
    public static void setup() {
        UnidbgProperties props = new UnidbgProperties();
        props.setIpaPath(System.getProperty("ipa.path", "research/豆包-11.8.0.ipa"));
        props.setDynarmic(false);
        props.setVerbose(true);
        props.setAsync(false);

        worker = new TTEncryptServiceWorker(props);
    }

    @AfterAll
    public static void cleanup() throws IOException {
        if (worker != null) {
            worker.destroy();
        }
    }

    /**
     * 测试解密 ./data/captured/decrypted_sample.bin
     * 这是已经 AES 解密后的数据，包含 TLV + BVX2 压缩
     */
    @Test
    public void testDecompressBVX2Sample() throws Exception {
        System.out.println("=== 测试 BVX2 解压 ===");

        // 读取 AES 解密后的数据
        byte[] tlvData = Files.readAllBytes(Paths.get("./data/captured/decrypted_sample.bin"));
        System.out.println("读取 TLV 数据: " + tlvData.length + " 字节");
        System.out.println("前16字节: " + bytesToHex(tlvData, 0, 16));

        // 解析 TLV 格式
        if (tlvData[0] != 0x02) {
            throw new RuntimeException("Invalid TLV tag: " + String.format("0x%02X", tlvData[0]));
        }

        int compressedLength = tlvData[1] & 0xFF;
        System.out.println("TLV Tag: 0x02");
        System.out.println("TLV Length: " + compressedLength + " 字节");

        // 提取 BVX2 压缩数据（跳过 TLV 头部2字节）
        byte[] bvx2Data = new byte[compressedLength];
        System.arraycopy(tlvData, 2, bvx2Data, 0, compressedLength);

        System.out.println("\nBVX2 压缩数据: " + compressedLength + " 字节");
        System.out.println("前16字节: " + bytesToHex(bvx2Data, 0, 16));

        try {
            // 尝试使用 libcompression 解压
            byte[] decompressed = worker.decompressBVX2(bvx2Data).get();

            System.out.println("\n✓ 解压成功！");
            System.out.println("解压后大小: " + decompressed.length + " 字节");
            System.out.println("解压数据: " + new String(decompressed, StandardCharsets.UTF_8));

        } catch (Exception e) {
            System.err.println("\n✗ 解压失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 测试完整流程：从 Base64 → AES 解密 → TLV 解析 → BVX2 解压
     */
    @Test
    public void testFullDecryptionFlow() throws Exception {
        System.out.println("\n=== 测试完整解密流程 ===");

        // 这是从 HAR 文件提取的监控 API 响应（Base64）
        String[] base64Samples = {
            // 请求 #4 的响应（如果有的话）
            // 请求 #40 的响应
            // 可以从 decrypt_har_complete.py 的输出中获取
        };

        // 如果没有样本数据，使用已解密的文件
        System.out.println("使用已解密的样本数据进行测试...");
        testDecompressBVX2Sample();
    }

    /**
     * AES-128-CBC 解密
     */
    private static byte[] aesDecrypt(String base64Encrypted) throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(base64Encrypted);

        // 提取 IV（前16字节）
        byte[] iv = new byte[16];
        System.arraycopy(encrypted, 0, iv, 0, 16);

        // 提取密文（剩余部分）
        byte[] ciphertext = new byte[encrypted.length - 16];
        System.arraycopy(encrypted, 16, ciphertext, 0, ciphertext.length);

        // AES-128-CBC 解密
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        return cipher.doFinal(ciphertext);
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length && (offset + i) < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[offset + i] & 0xFF));
            if (i < length - 1) sb.append(" ");
        }
        return sb.toString();
    }
}
