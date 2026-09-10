package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.BVX2DecompressionService;
import com.anjia.unidbgserver.service.TTEncryptServiceWorker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * BVX2 解压 API
 * 用于测试监控 API 的 BVX2 解压功能
 */
@RestController
@RequestMapping("/api/bvx2")
public class BVX2Controller {

    private static final Logger log = LoggerFactory.getLogger(BVX2Controller.class);

    @Autowired
    private TTEncryptServiceWorker ttEncryptServiceWorker;

    @Autowired
    private BVX2DecompressionService bvx2DecompressionService;

    /**
     * 解压 BVX2 格式的数据
     *
     * POST /api/bvx2/decompress
     * Content-Type: application/json
     *
     * 请求体:
     * {
     *   "data": "base64编码的BVX2数据",
     *   "encoding": "base64" (可选，默认 base64)
     * }
     *
     * 响应:
     * {
     *   "success": true,
     *   "decompressed": "解压后的数据 (UTF-8)",
     *   "decompressedHex": "解压后的数据 (十六进制)",
     *   "originalSize": 87,
     *   "decompressedSize": 234
     * }
     */
    @PostMapping("/decompress")
    public ResponseEntity<Map<String, Object>> decompress(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            String dataStr = request.get("data");
            String encoding = request.getOrDefault("encoding", "base64");

            if (dataStr == null || dataStr.isEmpty()) {
                response.put("success", false);
                response.put("error", "Missing 'data' field");
                return ResponseEntity.badRequest().body(response);
            }

            // 解码输入数据
            byte[] bvx2Data;
            if ("base64".equals(encoding)) {
                bvx2Data = Base64.getDecoder().decode(dataStr);
            } else if ("hex".equals(encoding)) {
                bvx2Data = hexToBytes(dataStr);
            } else {
                bvx2Data = dataStr.getBytes(StandardCharsets.UTF_8);
            }

            log.info("收到 BVX2 解压请求，数据长度: {} 字节", bvx2Data.length);
            log.debug("前16字节: {}", bytesToHex(bvx2Data, 0, Math.min(16, bvx2Data.length)));

            // 先尝试纯 Java 实现（快速且稳定）
            byte[] decompressed = null;
            try {
                decompressed = bvx2DecompressionService.decompress(bvx2Data);
                log.info("✓ 使用纯 Java 解压成功！原始大小: {}, 解压后: {}", bvx2Data.length, decompressed.length);
            } catch (Exception e1) {
                log.warn("纯 Java 解压失败: {}, 尝试 unidbg...", e1.getMessage());

                // 备用方案：使用 unidbg + libcompression
                try {
                    CompletableFuture<byte[]> future = ttEncryptServiceWorker.decompressBVX2(bvx2Data);
                    decompressed = future.get();
                    log.info("✓ 使用 unidbg 解压成功！原始大小: {}, 解压后: {}", bvx2Data.length, decompressed.length);
                } catch (Exception e2) {
                    log.error("unidbg 解压也失败: {}", e2.getMessage());
                    throw new RuntimeException("Both Java and unidbg decompression failed", e2);
                }
            }

            // 构造响应
            response.put("success", true);
            response.put("originalSize", bvx2Data.length);
            response.put("decompressedSize", decompressed.length);
            response.put("decompressedHex", bytesToHex(decompressed, 0, decompressed.length));

            // 尝试解码为 UTF-8 字符串
            try {
                String decompressedStr = new String(decompressed, StandardCharsets.UTF_8);
                response.put("decompressed", decompressedStr);
            } catch (Exception e) {
                response.put("decompressed", "(binary data, see decompressedHex)");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("BVX2 解压失败", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 解压 TLV + BVX2 格式的数据
     *
     * POST /api/bvx2/decompress-tlv
     *
     * 请求体:
     * {
     *   "data": "base64编码的TLV数据 (包含 Tag=0x02, Length, BVX2数据)"
     * }
     */
    @PostMapping("/decompress-tlv")
    public ResponseEntity<Map<String, Object>> decompressTLV(@RequestBody Map<String, String> request) {
        Map<String, Object> response = new HashMap<>();

        try {
            String dataStr = request.get("data");
            if (dataStr == null || dataStr.isEmpty()) {
                response.put("success", false);
                response.put("error", "Missing 'data' field");
                return ResponseEntity.badRequest().body(response);
            }

            byte[] tlvData = Base64.getDecoder().decode(dataStr);
            log.info("收到 TLV+BVX2 解压请求，数据长度: {} 字节", tlvData.length);

            // 解析 TLV
            if (tlvData.length < 2) {
                throw new IllegalArgumentException("TLV data too short");
            }

            int tag = tlvData[0] & 0xFF;
            int length = tlvData[1] & 0xFF;

            log.info("TLV Tag: 0x{}, Length: {}", Integer.toHexString(tag), length);

            if (tag != 0x02) {
                throw new IllegalArgumentException("Invalid TLV tag: 0x" + Integer.toHexString(tag));
            }

            if (tlvData.length < 2 + length) {
                throw new IllegalArgumentException("TLV data incomplete");
            }

            // 提取 BVX2 数据
            byte[] bvx2Data = new byte[length];
            System.arraycopy(tlvData, 2, bvx2Data, 0, length);

            log.debug("BVX2 数据前16字节: {}", bytesToHex(bvx2Data, 0, Math.min(16, bvx2Data.length)));

            // 先尝试纯 Java 实现（快速且稳定）
            byte[] decompressed = null;
            try {
                decompressed = bvx2DecompressionService.decompress(bvx2Data);
                log.info("✓ 使用纯 Java 解压成功！BVX2 大小: {}, 解压后: {}", bvx2Data.length, decompressed.length);
            } catch (Exception e1) {
                log.warn("纯 Java 解压失败: {}, 尝试 unidbg...", e1.getMessage());

                // 备用方案：使用 unidbg + libcompression
                try {
                    CompletableFuture<byte[]> future = ttEncryptServiceWorker.decompressBVX2(bvx2Data);
                    decompressed = future.get();
                    log.info("✓ 使用 unidbg 解压成功！BVX2 大小: {}, 解压后: {}", bvx2Data.length, decompressed.length);
                } catch (Exception e2) {
                    log.error("unidbg 解压也失败: {}", e2.getMessage());
                    throw new RuntimeException("Both Java and unidbg decompression failed", e2);
                }
            }

            // 构造响应
            response.put("success", true);
            response.put("tlvTag", String.format("0x%02X", tag));
            response.put("tlvLength", length);
            response.put("decompressedSize", decompressed.length);
            response.put("decompressedHex", bytesToHex(decompressed, 0, decompressed.length));

            try {
                String decompressedStr = new String(decompressed, StandardCharsets.UTF_8);
                response.put("decompressed", decompressedStr);
            } catch (Exception e) {
                response.put("decompressed", "(binary data)");
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("TLV+BVX2 解压失败", e);
            response.put("success", false);
            response.put("error", e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * 健康检查
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("service", "BVX2 Decompression");
        return ResponseEntity.ok(response);
    }

    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length && (offset + i) < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * 十六进制字符串转字节数组
     */
    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
