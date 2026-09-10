package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.LocationEncryptService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/location")
public class LocationEncryptController {

    private static final Logger log = LoggerFactory.getLogger(LocationEncryptController.class);

    @Autowired
    private LocationEncryptService locationEncryptService;

    /**
     * 加密 location 数据
     * POST /api/location/encrypt
     *
     * 请求体:
     * {
     *   "is_proxy": 1,
     *   "is_vpn": 1,
     *   "region_info": {
     *     "locale": "zh-CN",
     *     "system_language": "zh",
     *     "system_region": "CN"
     *   },
     *   "status": {
     *     "device_type": 1,
     *     "is_bluetooth_open": 1,
     *     "location_mode": 16,
     *     "permission": 30,
     *     "restricted_mode": 2,
     *     "system_language": "zh-Hans-CN",
     *     "system_region": "CN"
     *   },
     *   "timestamp": 1786212669,
     *   "upload_source": "bdlocation_boot_upload_device_info"
     * }
     */
    @PostMapping("/encrypt")
    public Map<String, Object> encryptLocationData(@RequestBody String jsonData) {
        Map<String, Object> result = new HashMap<>();

        try {
            log.info("收到 location 加密请求");

            long startTime = System.currentTimeMillis();
            String encrypted = locationEncryptService.encryptLocationData(jsonData);
            long duration = System.currentTimeMillis() - startTime;

            if (encrypted != null) {
                result.put("success", true);
                result.put("encrypted", encrypted);
                result.put("duration_ms", duration);
                log.info("加密成功，耗时 {} ms", duration);
            } else {
                result.put("success", false);
                result.put("error", "加密失败");
                log.error("加密失败");
            }
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("加密异常", e);
        }

        return result;
    }

    /**
     * base64 编码（对应 BDLEncryptUtil.base64StringWithDictionary）
     * POST /api/location/base64
     */
    @PostMapping("/base64")
    public Map<String, Object> base64Encode(@RequestBody String jsonData) {
        Map<String, Object> result = new HashMap<>();

        try {
            log.info("收到 base64 编码请求");

            long startTime = System.currentTimeMillis();
            String encoded = locationEncryptService.base64StringWithDictionary(jsonData);
            long duration = System.currentTimeMillis() - startTime;

            if (encoded != null) {
                result.put("success", true);
                result.put("encoded", encoded);
                result.put("duration_ms", duration);
                log.info("编码成功，耗时 {} ms", duration);
            } else {
                result.put("success", false);
                result.put("error", "编码失败");
                log.error("编码失败");
            }
        } catch (Exception e) {
            result.put("success", false);
            result.put("error", e.getMessage());
            log.error("编码异常", e);
        }

        return result;
    }

    /**
     * 健康检查
     */
    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> result = new HashMap<>();
        result.put("service", "LocationEncryptService");
        result.put("status", "running");
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }
}
