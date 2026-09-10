package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * BVX2 解压服务 - 纯 Java 实现
 *
 * BVX2 是 ByteDance 的自定义压缩格式，基于标准压缩算法
 * 通过分析发现可能使用 DEFLATE 或 LZFSE 算法
 */
@Service
public class BVX2DecompressionService {

    private static final Logger log = LoggerFactory.getLogger(BVX2DecompressionService.class);

    /**
     * 解压 BVX2 数据
     *
     * @param compressed BVX2 压缩数据
     * @return 解压后的数据
     */
    public byte[] decompress(byte[] compressed) {
        log.debug("尝试解压 BVX2 数据，长度: {}", compressed.length);

        if (compressed.length < 4) {
            throw new IllegalArgumentException("Data too short for BVX2 format");
        }

        // 显示前16字节
        StringBuilder hexStr = new StringBuilder();
        for (int i = 0; i < Math.min(16, compressed.length); i++) {
            hexStr.append(String.format("%02x ", compressed[i] & 0xFF));
        }
        log.debug("前16字节: {}", hexStr);

        // 尝试多种解压方法
        Exception lastException = null;

        // 方法1: 直接 DEFLATE (raw)
        try {
            byte[] result = tryRawDeflate(compressed);
            if (result != null && result.length > 0) {
                log.info("✓ 使用 Raw DEFLATE 解压成功，大小: {}", result.length);
                return result;
            }
        } catch (Exception e) {
            log.debug("Raw DEFLATE 失败: {}", e.getMessage());
            lastException = e;
        }

        // 方法2: DEFLATE with ZLIB wrapper
        try {
            byte[] result = tryZlibDeflate(compressed);
            if (result != null && result.length > 0) {
                log.info("✓ 使用 ZLIB DEFLATE 解压成功，大小: {}", result.length);
                return result;
            }
        } catch (Exception e) {
            log.debug("ZLIB DEFLATE 失败: {}", e.getMessage());
            lastException = e;
        }

        // 方法3: GZIP
        try {
            byte[] result = tryGzip(compressed);
            if (result != null && result.length > 0) {
                log.info("✓ 使用 GZIP 解压成功，大小: {}", result.length);
                return result;
            }
        } catch (Exception e) {
            log.debug("GZIP 失败: {}", e.getMessage());
            lastException = e;
        }

        // 方法4: 跳过头部后尝试 DEFLATE
        if (compressed.length > 8) {
            try {
                byte[] withoutHeader = new byte[compressed.length - 4];
                System.arraycopy(compressed, 4, withoutHeader, 0, withoutHeader.length);

                byte[] result = tryRawDeflate(withoutHeader);
                if (result != null && result.length > 0) {
                    log.info("✓ 跳过4字节头部后使用 Raw DEFLATE 解压成功，大小: {}", result.length);
                    return result;
                }
            } catch (Exception e) {
                log.debug("跳过头部后 DEFLATE 失败: {}", e.getMessage());
                lastException = e;
            }
        }

        // 所有方法都失败
        String errorMsg = "All decompression methods failed";
        if (lastException != null) {
            errorMsg += ": " + lastException.getMessage();
        }
        throw new RuntimeException(errorMsg, lastException);
    }

    /**
     * 尝试使用 Raw DEFLATE 解压
     */
    private byte[] tryRawDeflate(byte[] data) throws DataFormatException {
        Inflater inflater = new Inflater(true); // nowrap=true for raw DEFLATE
        try {
            inflater.setInput(data);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];

            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0) {
                    break;
                }
                outputStream.write(buffer, 0, count);
            }

            byte[] result = outputStream.toByteArray();
            if (result.length > 0) {
                return result;
            }

            return null;
        } finally {
            inflater.end();
        }
    }

    /**
     * 尝试使用 ZLIB DEFLATE 解压
     */
    private byte[] tryZlibDeflate(byte[] data) throws DataFormatException {
        Inflater inflater = new Inflater(false); // nowrap=false for ZLIB
        try {
            inflater.setInput(data);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];

            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0) {
                    break;
                }
                outputStream.write(buffer, 0, count);
            }

            byte[] result = outputStream.toByteArray();
            if (result.length > 0) {
                return result;
            }

            return null;
        } finally {
            inflater.end();
        }
    }

    /**
     * 尝试使用 GZIP 解压
     */
    private byte[] tryGzip(byte[] data) {
        try {
            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(data);
            java.util.zip.GZIPInputStream gis = new java.util.zip.GZIPInputStream(bis);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            byte[] buffer = new byte[4096];
            int len;
            while ((len = gis.read(buffer)) > 0) {
                outputStream.write(buffer, 0, len);
            }

            gis.close();
            return outputStream.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }
}
