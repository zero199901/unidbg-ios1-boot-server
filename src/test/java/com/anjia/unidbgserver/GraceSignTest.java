package com.anjia.unidbgserver.service;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.DarwinEmulatorBuilder;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 简化版 Grace 签名调用测试
 * 直接加载 Grace 二进制并尝试调用签名函数
 */
@Slf4j
public class GraceSignTest {

    private final Emulator<DarwinFileIO> emulator;
    private final Module graceModule;

    // 从 frida 发现的函数偏移
    private static final long SIGN_FUNC = 0x641994L;

    public GraceSignTest(String gracePath) throws IOException {
        File graceFile = new File(gracePath);
        if (!graceFile.exists()) {
            throw new IllegalArgumentException("Grace 文件不存在: " + gracePath);
        }

        // 创建模拟器
        emulator = DarwinEmulatorBuilder.for64Bit()
            .setProcessName(graceFile.getName())
            .setRootDir(new File("target"))
            .build();

        emulator.getBackend().registerEmuCountHook(10000);

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());

        // 加载 Grace
        MachOLoader loader = (MachOLoader) memory;
        graceModule = loader.load(graceFile);

        log.info("Grace 加载完成，基地址: 0x{}", Long.toHexString(graceModule.base));
    }

    /**
     * 测试调用签名函数
     */
    public Map<String, String> testSign(String url, String body) {
        MemoryBlock urlBlock = null;
        MemoryBlock bodyBlock = null;
        MemoryBlock outputBlock = null;

        try {
            long khronos = System.currentTimeMillis() / 1000;

            // 分配内存
            byte[] urlBytes = url.getBytes(StandardCharsets.UTF_8);
            byte[] bodyBytes = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];

            urlBlock = emulator.getMemory().malloc(urlBytes.length + 1, true);
            bodyBlock = emulator.getMemory().malloc(Math.max(bodyBytes.length, 1), true);
            outputBlock = emulator.getMemory().malloc(4096, true);

            UnidbgPointer urlPtr = urlBlock.getPointer();
            UnidbgPointer bodyPtr = bodyBlock.getPointer();
            UnidbgPointer outputPtr = outputBlock.getPointer();

            urlPtr.write(urlBytes);
            urlPtr.setByte(urlBytes.length, (byte) 0);

            if (bodyBytes.length > 0) {
                bodyPtr.write(bodyBytes);
            }

            log.info("尝试调用 Grace+0x{} ...", Long.toHexString(SIGN_FUNC));
            log.info("  url: {}", url);
            log.info("  body: {}", body);
            log.info("  khronos: {}", khronos);

            // 尝试不同的函数签名
            // 方案1: func(char* url, char* body, int body_len, long khronos, char* output)
            try {
                Number ret = emulator.eFunc(graceModule.base + SIGN_FUNC,
                    urlPtr.peer,
                    bodyPtr.peer,
                    bodyBytes.length,
                    khronos,
                    outputPtr.peer);

                log.info("函数返回: {}", ret);

                // 尝试读取输出
                String output = outputPtr.getString(0);
                if (output != null && output.length() > 0) {
                    log.info("输出字符串: {}", output);

                    Map<String, String> result = new HashMap<>();
                    result.put("output", output);
                    result.put("x-khronos", String.valueOf(khronos));
                    return result;
                }

                // 尝试读取二进制数据
                byte[] outputBytes = outputPtr.getByteArray(0, 200);
                StringBuilder hex = new StringBuilder();
                for (byte b : outputBytes) {
                    hex.append(String.format("%02x", b & 0xff));
                    if (hex.length() > 100) break;
                }
                log.info("输出十六进制: {}", hex);

            } catch (Exception e) {
                log.error("调用失败: {}", e.getMessage());
            }

        } finally {
            if (urlBlock != null) urlBlock.free();
            if (bodyBlock != null) bodyBlock.free();
            if (outputBlock != null) outputBlock.free();
        }

        return null;
    }

    public void destroy() throws IOException {
        if (emulator != null) {
            emulator.close();
        }
    }

    // 测试用
    public static void main(String[] args) {
        try {
            GraceSignTest test = new GraceSignTest("/tmp/Grace_binary");

            Map<String, String> result = test.testSign(
                "https://api.doubao.com/v1/chat?aid=482431",
                "{\"message\":\"hello\"}"
            );

            if (result != null) {
                System.out.println("\n=== 签名结果 ===");
                result.forEach((k, v) -> System.out.println(k + ": " + v));
            } else {
                System.out.println("签名生成失败");
            }

            test.destroy();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
