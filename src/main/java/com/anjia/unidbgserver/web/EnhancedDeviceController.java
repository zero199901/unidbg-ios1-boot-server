package com.anjia.unidbgserver.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.service.EnhancedDeviceFingerprintService;
import com.anjia.unidbgserver.service.EnhancedDeviceFingerprintService.DeviceFingerprint;
import com.anjia.unidbgserver.service.TTEncryptServiceWorker;
import com.anjia.unidbgserver.service.GorgonServiceWorker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.*;

/**
 * 增强的设备注册控制器
 * 基于Frida逆向分析结果实现
 */
@RestController
@RequestMapping(path = "/api/enhanced", produces = MediaType.APPLICATION_JSON_VALUE)
public class EnhancedDeviceController {
    private static final Logger log = LoggerFactory.getLogger(EnhancedDeviceController.class);


    @Resource
    private EnhancedDeviceFingerprintService fingerprintService;

    @Resource(name = "ttEncryptWorker")
    private TTEncryptServiceWorker ttEncryptWorker;

    @Resource(name = "gorgonWorker")
    private GorgonServiceWorker gorgonWorker;

    /**
     * 生成新的设备指纹
     * GET /api/enhanced/fingerprint
     */
    @GetMapping("fingerprint")
    public Map<String, Object> generateFingerprint() {
        DeviceFingerprint fingerprint = fingerprintService.generateFullFingerprint();

        Map<String, Object> result = new HashMap<>();
        result.put("idfv", fingerprint.getIdfv());
        result.put("openudid", fingerprint.getOpenudid());
        result.put("clientudid", fingerprint.getClientudid());
        result.put("device_model", fingerprint.getDeviceModel());
        result.put("ios_version", fingerprint.getIosVersion());
        result.put("device_id", fingerprint.getDeviceId());
        result.put("install_id", fingerprint.getInstallId());

        log.info("生成设备指纹: device_id={}", fingerprint.getDeviceId());
        return result;
    }

    /**
     * 测试设备注册（使用增强的设备指纹）
     * POST /api/enhanced/register
     */
    @PostMapping("register")
    public Map<String, Object> testRegister() {
        try {
            // 生成设备指纹
            DeviceFingerprint fingerprint = fingerprintService.generateFullFingerprint();

            // 构造注册请求body
            Map<String, Object> body = buildRegistrationBody(fingerprint);

            // TC加密
            String bodyJson = com.alibaba.fastjson.JSON.toJSONString(body);
            byte[] encryptedBody = ttEncryptWorker.ttEncrypt(null, bodyJson).get();

            // 构造URL
            String url = buildRegistrationUrl(fingerprint);

            // 生成签名（修正方法名）
            Map<String, String> signs = gorgonWorker.getGorgon(url, bodyJson.getBytes()).get();

            // 返回测试结果（不实际发送请求）
            Map<String, Object> result = new HashMap<>();
            result.put("status", "prepared");
            result.put("fingerprint", Map.of(
                "idfv", fingerprint.getIdfv(),
                "device_id", fingerprint.getDeviceId(),
                "install_id", fingerprint.getInstallId()
            ));
            result.put("url_length", url.length());
            result.put("encrypted_body_length", encryptedBody.length);
            result.put("has_signs", !signs.isEmpty());
            result.put("message", "设备注册请求已准备就绪（基于Frida分析）");

            log.info("测试注册完成: device_id={}", fingerprint.getDeviceId());
            return result;

        } catch (Exception e) {
            log.error("测试注册失败", e);
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return error;
        }
    }

    /**
     * 重置设备指纹
     * POST /api/enhanced/reset
     */
    @PostMapping("reset")
    public Map<String, Object> resetFingerprint() {
        fingerprintService.resetFingerprint();

        Map<String, Object> result = new HashMap<>();
        result.put("status", "success");
        result.put("message", "设备指纹已重置");
        return result;
    }

    /**
     * 构造注册请求URL
     */
    private String buildRegistrationUrl(DeviceFingerprint fingerprint) {
        StringBuilder url = new StringBuilder("https://api5-normal-gl.doubao.com/service/2/device_register/?");

        Map<String, String> params = new LinkedHashMap<>();
        params.put("device_id", String.valueOf(fingerprint.getDeviceId()));
        params.put("is_activated", "1");  // Frida发现：真实请求用1
        params.put("aid", "482431");
        params.put("tt_data", "a");
        params.put("app_name", "nova_ai");
        params.put("update_version_code", "11080033");
        params.put("language", "zh");
        params.put("version_code", "11.8.0");
        params.put("ac", "WIFI");
        params.put("device_type", fingerprint.getDeviceModel());
        params.put("iid", String.valueOf(fingerprint.getInstallId()));
        params.put("device_platform", "iphone");
        params.put("channel", "App Store");
        params.put("version_name", "11.8.0");
        params.put("os_version", fingerprint.getIosVersion());
        params.put("openudid", fingerprint.getOpenudid());
        params.put("region", "CN");

        params.forEach((k, v) -> {
            if (url.charAt(url.length() - 1) != '?') {
                url.append("&");
            }
            url.append(k).append("=").append(v);
        });

        return url.toString();
    }

    /**
     * 构造注册请求body
     * 基于Frida分析的真实结构
     */
    private Map<String, Object> buildRegistrationBody(DeviceFingerprint fingerprint) {
        Map<String, Object> body = new HashMap<>();

        // magic_tag
        body.put("magic_tag", "ss_app_log");

        // header
        Map<String, Object> header = new HashMap<>();
        header.put("display_name", "豆包");
        header.put("update_version_code", 11080033);
        header.put("manifest_version_code", 11080033);
        header.put("aid", 482431);
        header.put("app_version", "11.8.0");
        header.put("version_code", 11080033);
        header.put("package", "com.bot.doubao");
        header.put("channel", "App Store");
        header.put("device_id", fingerprint.getDeviceId());
        header.put("device_type", fingerprint.getDeviceModel());
        header.put("device_brand", "iPhone");
        header.put("os", "iOS");
        header.put("os_version", fingerprint.getIosVersion());
        header.put("os_api", 18);
        header.put("language", "zh-Hans-CN");
        header.put("resolution", "414x896");
        header.put("display_density", "3.0");
        header.put("timezone", 8);
        header.put("access", "WIFI");
        header.put("rom", fingerprint.getIosVersion());
        header.put("rom_version", fingerprint.getIosVersion());
        header.put("openudid", fingerprint.getOpenudid());
        header.put("clientudid", fingerprint.getClientudid());
        header.put("sdk_version", "3.9.6.7");
        header.put("cpu_abi", "arm64");
        header.put("region", "CN");
        header.put("sys_region", "CN");

        body.put("header", header);
        body.put("device_id", fingerprint.getDeviceId());

        return body;
    }
}
