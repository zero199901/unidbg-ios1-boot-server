package com.anjia.unidbgserver.service;

import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * 设备指纹服务 - 基于Frida逆向分析结果
 * 实现真实的iOS设备指纹生成逻辑
 */
@Service
public class EnhancedDeviceFingerprintService {

    // KeyChain模拟存储
    private final Map<String, Object> keyChainStorage = new ConcurrentHashMap<>();

    /**
     * 设备指纹完整信息
     */
    public static class DeviceFingerprint {
        private String idfv;
        private String openudid;
        private String clientudid;
        private String deviceModel;
        private String iosVersion;
        private String deviceBrand;
        private Long deviceId;
        private Long installId;

        // Getters and Setters
        public String getIdfv() { return idfv; }
        public void setIdfv(String idfv) { this.idfv = idfv; }

        public String getOpenudid() { return openudid; }
        public void setOpenudid(String openudid) { this.openudid = openudid; }

        public String getClientudid() { return clientudid; }
        public void setClientudid(String clientudid) { this.clientudid = clientudid; }

        public String getDeviceModel() { return deviceModel; }
        public void setDeviceModel(String deviceModel) { this.deviceModel = deviceModel; }

        public String getIosVersion() { return iosVersion; }
        public void setIosVersion(String iosVersion) { this.iosVersion = iosVersion; }

        public String getDeviceBrand() { return deviceBrand; }
        public void setDeviceBrand(String deviceBrand) { this.deviceBrand = deviceBrand; }

        public Long getDeviceId() { return deviceId; }
        public void setDeviceId(Long deviceId) { this.deviceId = deviceId; }

        public Long getInstallId() { return installId; }
        public void setInstallId(Long installId) { this.installId = installId; }
    }

    public EnhancedDeviceFingerprintService() {
        initializeKeyChain();
    }

    private void initializeKeyChain() {
        keyChainStorage.put("com.bytedance.safeguard.service", generateSafeguardData());
        keyChainStorage.put("kBDCommonClientABStorageManagerServerSettingFeatureUserDefaultKey", "{}");
        System.out.println("[EnhancedDeviceFingerprint] KeyChain存储初始化完成");
    }

    public String generateIDFV() {
        String stored = (String) keyChainStorage.get("IDFV");
        if (stored != null) {
            return stored;
        }

        String idfv = UUID.randomUUID().toString().toUpperCase();
        keyChainStorage.put("IDFV", idfv);
        System.out.println("[EnhancedDeviceFingerprint] 生成新的IDFV: " + idfv);
        return idfv;
    }

    public String generateOpenUDID() {
        String stored = (String) keyChainStorage.get("OpenUDID");
        if (stored != null) {
            return stored;
        }

        String openudid = UUID.randomUUID().toString().replace("-", "").toLowerCase();
        keyChainStorage.put("OpenUDID", openudid);
        System.out.println("[EnhancedDeviceFingerprint] 生成新的OpenUDID: " + openudid);
        return openudid;
    }

    public String generateClientUDID() {
        return UUID.randomUUID().toString().toUpperCase();
    }

    public String getDeviceModel() {
        String[] models = {"iPhone12,1", "iPhone13,2", "iPhone14,5", "iPhone15,2"};
        return models[(int) (Math.random() * models.length)];
    }

    public String getIOSVersion() {
        String[] versions = {"15.6", "16.1", "16.3.1", "16.5", "17.0"};
        return versions[(int) (Math.random() * versions.length)];
    }

    private String generateSafeguardData() {
        return UUID.randomUUID().toString();
    }

    public Object secItemCopyMatching(String service, String account) {
        String key = service + ":" + account;
        Object value = keyChainStorage.get(key);
        if (value == null) {
            value = keyChainStorage.get(service);
        }
        return value;
    }

    public int secItemAdd(String service, String account, Object data) {
        String key = service + ":" + account;
        keyChainStorage.put(key, data);
        return 0;
    }

    public DeviceFingerprint generateFullFingerprint() {
        DeviceFingerprint fingerprint = new DeviceFingerprint();

        fingerprint.setIdfv(generateIDFV());
        fingerprint.setOpenudid(generateOpenUDID());
        fingerprint.setClientudid(generateClientUDID());
        fingerprint.setDeviceModel(getDeviceModel());
        fingerprint.setIosVersion(getIOSVersion());
        fingerprint.setDeviceBrand("iPhone");

        long baseId = 2180000000000000L;
        fingerprint.setDeviceId(baseId + (long)(Math.random() * 9999999999L));
        fingerprint.setInstallId(fingerprint.getDeviceId() + 4096);

        System.out.println("[EnhancedDeviceFingerprint] 生成完整设备指纹:");
        System.out.println("  IDFV: " + fingerprint.getIdfv());
        System.out.println("  OpenUDID: " + fingerprint.getOpenudid());
        System.out.println("  ClientUDID: " + fingerprint.getClientudid());
        System.out.println("  Device ID: " + fingerprint.getDeviceId());

        return fingerprint;
    }

    public void resetFingerprint() {
        keyChainStorage.remove("IDFV");
        keyChainStorage.remove("OpenUDID");
        System.out.println("[EnhancedDeviceFingerprint] 设备指纹已重置");
    }
}
