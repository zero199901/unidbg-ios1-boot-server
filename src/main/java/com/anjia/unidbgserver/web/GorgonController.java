package com.anjia.unidbgserver.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.service.GorgonServiceWorker;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping(path = "/api/gorgon", produces = MediaType.APPLICATION_JSON_VALUE)
public class GorgonController {
    private static final Logger log = LoggerFactory.getLogger(GorgonController.class);


    @Resource(name = "gorgonWorker")
    private GorgonServiceWorker gorgonServiceWorker;

    /**
     * POST /api/gorgon/sign
     *
     * 请求参数：
     *   - url: 完整 URL（含 query 参数）
     *   - body: 请求体（可选，默认空）
     *
     * 返回：
     * {
     *   "x-gorgon": "840480640000e98e...",
     *   "x-khronos": "1786099533",
     *   "x-ladon": "n34oYNYL/Sw..."
     * }
     */
    @PostMapping(value = "sign")
    public Map<String, String> sign(
        @RequestParam String url,
        @RequestParam(required = false) String cookie,
        @RequestBody(required = false) String body
    ) throws Exception {
        byte[] bodyBytes = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];

        Map<String, String> headers = gorgonServiceWorker.getGorgon(url, bodyBytes, cookie).get();

        log.info("Gorgon 签名: url={}, body.len={}, cookie={}",
            url.length() > 50 ? url.substring(0, 50) + "..." : url,
            bodyBytes.length,
            cookie != null ? "yes(c0)" : "no(80)");

        return headers;
    }

    /**
     * GET /api/gorgon/sign?url=xxx&body=xxx  （快速测试用）
     */
    @GetMapping(value = "sign")
    public Map<String, String> signGet(
        @RequestParam String url,
        @RequestParam(required = false, defaultValue = "") String body,
        @RequestParam(required = false) String cookie
    ) throws Exception {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        return gorgonServiceWorker.getGorgon(url, bodyBytes, cookie).get();
    }
}
