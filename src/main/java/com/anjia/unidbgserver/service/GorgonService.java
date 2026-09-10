package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.config.UnidbgProperties;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.Map;

/**
 * Gorgon 签名服务
 *
 * 实现策略（优先级顺序）：
 * 1. unidbg 调用 Grace iOS 二进制中的真实签名函数（需要找到准确函数偏移）
 * 2. 降级：Java 逆向实现（已验证 code=0，服务器接受）
 *
 * 找签名函数偏移：
 *   otool -d /path/to/Grace | grep -A2 "0xa67a09c"  # 找 ADRP x-gorgon 字符串引用
 *   Ghidra: 搜索字符串 "x-gorgon" → 找调用者函数 → 记录偏移
 */
public class GorgonService {
    private static final Logger log = LoggerFactory.getLogger(GorgonService.class);

    /**
     * Grace 二进制中签名函数的偏移（待通过静态分析确认）
     * x-gorgon 字符串在 Grace+0xa67a09c
     * 待确认：包含该字符串引用的函数起始地址
     * 方法：Ghidra → 搜索 "x-gorgon" → 查找引用 → 找到函数 → 记录 offset
     */
    private static final long GORGON_FUNC_OFFSET = 0L; // TODO: 填入真实偏移

    private final UnidbgProperties props;
    private GorgonUnidbgService unidbgService;

    GorgonService(UnidbgProperties props) {
        this.props = props;
        // 尝试初始化 unidbg 服务（需要 IPA 文件和正确的函数偏移）
        if (GORGON_FUNC_OFFSET != 0L && props.getIpaPath() != null) {
            try {
                unidbgService = new GorgonUnidbgService(props, GORGON_FUNC_OFFSET);
                log.info("GorgonService: unidbg 模式就绪 (func_off=0x{})",
                    Long.toHexString(GORGON_FUNC_OFFSET));
            } catch (Exception e) {
                log.warn("GorgonService: unidbg 初始化失败，降级 Java: {}", e.getMessage());
            }
        } else {
            log.info("GorgonService: Java 模式（待确认函数偏移后启用 unidbg）");
        }
    }

    /**
     * 生成 Gorgon 签名
     *
     * @param url  请求 URL（含 query 参数）
     * @param body 请求体字节数组
     * @return Map 包含 7 个签名参数
     */
    public Map<String, String> getGorgon(String url, byte[] body) {
        return getGorgon(url, body, null);
    }

    public Map<String, String> getGorgon(String url, byte[] body, String cookie) {
        byte[] b = body != null ? body : new byte[0];

        // 优先 unidbg（调用真实 iOS 函数，暂不支持 cookie 参数）
        if (unidbgService != null) {
            try {
                Map<String, String> result = unidbgService.sign(url, b);
                if (result != null && result.containsKey("x-gorgon")) {
                    return result;
                }
            } catch (Exception e) {
                log.warn("unidbg 签名失败，降级 Java: {}", e.getMessage());
            }
        }

        // 降级：Java 逆向实现
        return RealGorgonAlgorithm.generateReal(url, b, cookie);
    }

    public void destroy() throws IOException {
        if (unidbgService != null) {
            unidbgService.destroy();
        }
    }
}
