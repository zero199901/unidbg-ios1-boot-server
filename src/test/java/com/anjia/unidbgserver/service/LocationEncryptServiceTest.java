package com.anjia.unidbgserver.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LocationEncryptServiceTest {

    @Test
    public void testEncryptDecrypt() {
        LocationEncryptService service = new LocationEncryptService();

        // 测试数据
        String json = "{\"status\":{\"restricted_mode\":2,\"permission\":30,\"is_bluetooth_open\":true,\"system_region\":\"CN\",\"system_language\":\"zh-Hans-CN\",\"location_mode\":16,\"device_type\":1},\"is_vpn\":true,\"is_proxy\":true,\"timestamp\":1786212104,\"upload_source\":\"bdlocation_boot_upload_device_info\",\"region_info\":{\"locale\":\"zh-CN\",\"system_language\":\"zh\",\"system_region\":\"CN\"}}";

        // 加密
        String encrypted = service.encryptLocationData(json);
        assertNotNull(encrypted);
        System.out.println("加密结果：" + encrypted);

        // 解密
        String decrypted = service.decryptLocationData(encrypted);
        assertEquals(json, decrypted);
        System.out.println("解密结果：" + decrypted);
    }

    @Test
    public void testWithRealSample() {
        LocationEncryptService service = new LocationEncryptService();

        // 从 frida 抓取的真实加密数据
        String realEncrypted = "5pe9vb/u6fzp6O6/vae95pe9vb29v+/47unv9P7p+PnC8PL5+L+9p72vsZe9vb29" +
                "v+347/D07u708vO/vae9rq2xl729vb2/9O7C//Ho+Ony8un1wvLt+PO/vae96e/o" +
                "+LGXvb29vb/u5O7p+PDC7/j69PLzv72nvb/e07+xl729vb2/7uTu6fjwwvH88/ro" +
                "/Pr4v72nvb/n9bDV/PPusN7Tv7GXvb29vb/x8v786fTy88Lw8vn4v72nvayrsZe9" +
                "vb29v/n46/T++MLp5O34v72nvayXvb3gsZe9vb/07sLr7fO/vae96e/o+LGXvb2/" +
                "9O7C7e/y5eS/vae96e/o+LGXvb2/6fTw+O7p/PDtv72nvayqpauvrK+sramxl729" +
                "v+jt8fL8+cLu8ujv/vi/vae9v//58fL+/On08vPC//Ly6cLo7fHy/PnC+fjr9P74" +
                "wvTz+/K/sZe9vb/v+Pr08vPC9PP78r+9p73ml729vb2/8fL+/PH4v72nvb/n9bDe" +
                "07+xl729vb2/7uTu6fjwwvH88/ro/Pr4v72nvb/n9b+xl729vb2/7uTu6fjwwu/4" +
                "+vTy87+9p72/3tO/l7294Jfg";

        // 解密
        String decrypted = service.decryptLocationData(realEncrypted);
        System.out.println("真实数据解密结果：");
        System.out.println(decrypted);

        // 验证可以解析为 JSON
        assertTrue(decrypted.contains("\"status\""));
        assertTrue(decrypted.contains("\"system_region\""));

        // 再次加密，验证结果一致
        String reEncrypted = service.encryptLocationData(decrypted);
        assertEquals(realEncrypted, reEncrypted);
        System.out.println("✅ 加密算法验证成功！");
    }
}
