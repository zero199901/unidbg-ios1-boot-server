package com.anjia.unidbgserver.service;

import org.junit.jupiter.api.Test;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * Gorgon 算法测试
 */
@Slf4j
class GorgonAlgorithmTest {

    @Test
    void testGorgonFormat() {
        // 测试数据
        String url = "https://p11-flow-imagex-sign.byteimg.com/test";
        byte[] body = "test body".getBytes();

        // 生成 Gorgon
        Map<String, String> headers = GorgonAlgorithm.generate(url, body);

        String gorgon = headers.get("x-gorgon");
        String khronos = headers.get("x-khronos");
        String ladon = headers.get("x-ladon");

        log.info("生成的 Gorgon 签名:");
        log.info("  x-gorgon:  {}", gorgon);
        log.info("  x-khronos: {}", khronos);
        log.info("  x-ladon:   {}", ladon);

        // 验证格式
        assert gorgon != null && gorgon.length() == 52 : "Gorgon 长度应为 52";
        assert gorgon.matches("[0-9a-f]{52}") : "Gorgon 应为52位十六进制";

        log.info("\nGorgon 格式分析:");
        log.info("  版本头(0-7):   {}", gorgon.substring(0, 8));
        log.info("  时间戳(8-15):  {}", gorgon.substring(8, 16));
        log.info("  哈希(16-47):   {}", gorgon.substring(16, 48));
        log.info("  校验(48-51):   {}", gorgon.substring(48, 52));

        log.info("\n对比真实样本:");
        log.info("  真实: 840480640000e98e59805211ad6ec628d34c5fa615ed6bd4f4e2");
        log.info("  生成: {}", gorgon);
    }

    @Test
    void testMultipleRequests() {
        // 测试多个不同请求
        String[] urls = {
            "https://api.doubao.com/v1/chat",
            "https://api.doubao.com/v1/message",
            "https://p11-flow-imagex-sign.byteimg.com/image.png"
        };

        for (String url : urls) {
            Map<String, String> headers = GorgonAlgorithm.generate(url, new byte[0]);
            log.info("URL: {} → x-gorgon: {}",
                url.substring(0, Math.min(40, url.length())),
                headers.get("x-gorgon").substring(0, 20) + "...");
        }
    }
}
