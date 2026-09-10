package com.anjia.unidbgserver;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.DarwinEmulatorBuilder;
import com.github.unidbg.ios.DarwinResolver;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * 直接测试 Grace 签名函数调用
 *
 * 目标：找到正确的函数地址和调用方式
 */
public class GraceDirectCall {

    public static void main(String[] args) throws Exception {
        System.out.println("========== Grace 签名函数直接调用测试 ==========\n");

        // 创建 ARM64 模拟器
        Emulator<DarwinFileIO> emulator = DarwinEmulatorBuilder.for64Bit()
            .setProcessName("Grace")
            .setRootDir(new File("target"))
            .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());

        // 加载 Grace 二进制
        File graceFile = new File("/tmp/Grace_binary");
        if (!graceFile.exists()) {
            System.err.println("Grace 二进制不存在: " + graceFile.getAbsolutePath());
            System.exit(1);
        }

        MachOLoader loader = (MachOLoader) memory;
        Module graceModule = loader.load(graceFile);

        System.out.println("✓ Grace 已加载");
        System.out.println("  基地址: 0x" + Long.toHexString(graceModule.base));
        System.out.println("  大小: 0x" + Long.toHexString(graceModule.size));
        System.out.println();

        // 测试数据（从真实 HAR 提取）
        String url = "https://api5-normal-gl.doubao.com/im/message/mark_conv_read?aid=482431";
        String body = "{\"cmd\":2100}";
        long khronos = 1786099533L;

        System.out.println("【测试输入】");
        System.out.println("  URL: " + url);
        System.out.println("  Body: " + body);
        System.out.println("  Khronos: " + khronos);
        System.out.println();

        // 尝试搜索签名函数的特征
        System.out.println("【搜索签名字符串位置】");

        // 已知的字符串偏移（从 frida 发现）
        long[] stringOffsets = {
            0xa67a09cL,  // x-gorgon
            0xa67a0b6L,  // x-argus
            0xa67a0a5L,  // x-ladon
            0xa663eecL   // x-ss-stub
        };

        String[] stringNames = {"x-gorgon", "x-argus", "x-ladon", "x-ss-stub"};

        for (int i = 0; i < stringOffsets.length; i++) {
            long addr = graceModule.base + stringOffsets[i];
            try {
                UnidbgPointer ptr = UnidbgPointer.pointer(emulator, addr);
                String str = ptr.getString(0);
                System.out.println("  0x" + Long.toHexString(stringOffsets[i]) + " -> \"" + str + "\"");
            } catch (Exception e) {
                System.out.println("  0x" + Long.toHexString(stringOffsets[i]) + " -> (读取失败)");
            }
        }
        System.out.println();

        // 尝试不同的函数签名调用方式
        System.out.println("【尝试调用签名函数】");
        System.out.println();

        // 候选函数地址
        long[] candidateFuncs = {
            0x641994L,   // MD5 高频调用点
            0x3f0ff60L,  // 另一个 MD5 热点
            0x3f0e880L   // SHA256 调用点
        };

        for (int i = 0; i < candidateFuncs.length; i++) {
            System.out.println(">>> 测试函数 #" + (i+1) + ": Grace+0x" + Long.toHexString(candidateFuncs[i]));

            try {
                testSignFunction(emulator, graceModule, candidateFuncs[i], url, body, khronos);
            } catch (Exception e) {
                System.out.println("    ✗ 调用失败: " + e.getMessage());
            }

            System.out.println();
        }

        emulator.close();
        System.out.println("========== 测试完成 ==========");
    }

    /**
     * 测试调用签名函数（尝试多种函数签名）
     */
    private static void testSignFunction(Emulator<?> emulator, Module module,
                                         long funcOffset, String url, String body, long khronos) {

        MemoryBlock urlBlock = null;
        MemoryBlock bodyBlock = null;
        MemoryBlock outputBlock = null;

        try {
            // 准备参数
            byte[] urlBytes = url.getBytes(StandardCharsets.UTF_8);
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);

            urlBlock = emulator.getMemory().malloc(urlBytes.length + 1, true);
            bodyBlock = emulator.getMemory().malloc(bodyBytes.length + 1, true);
            outputBlock = emulator.getMemory().malloc(4096, true);

            UnidbgPointer urlPtr = urlBlock.getPointer();
            UnidbgPointer bodyPtr = bodyBlock.getPointer();
            UnidbgPointer outputPtr = outputBlock.getPointer();

            urlPtr.write(urlBytes);
            urlPtr.setByte(urlBytes.length, (byte) 0);
            bodyPtr.write(bodyBytes);
            bodyPtr.setByte(bodyBytes.length, (byte) 0);

            long funcAddr = module.base + funcOffset;

            System.out.println("    尝试调用方式 1: func(url, body, body_len, khronos, output)");

            try {
                Number ret = emulator.eFunc(funcAddr,
                    urlPtr.peer,
                    bodyPtr.peer,
                    bodyBytes.length,
                    khronos,
                    outputPtr.peer);

                System.out.println("    ✓ 调用成功，返回值: " + ret);

                // 检查输出
                checkOutput(emulator, outputPtr, "output");

            } catch (Exception e) {
                System.out.println("    ✗ 方式 1 失败: " + e.getMessage());
            }

            // 清空输出缓冲区
            outputPtr.write(new byte[100]);

            System.out.println("    尝试调用方式 2: func(url, url_len, body, body_len, khronos, output)");

            try {
                Number ret = emulator.eFunc(funcAddr,
                    urlPtr.peer,
                    urlBytes.length,
                    bodyPtr.peer,
                    bodyBytes.length,
                    khronos,
                    outputPtr.peer);

                System.out.println("    ✓ 调用成功，返回值: " + ret);
                checkOutput(emulator, outputPtr, "output");

            } catch (Exception e) {
                System.out.println("    ✗ 方式 2 失败: " + e.getMessage());
            }

        } finally {
            if (urlBlock != null) urlBlock.free();
            if (bodyBlock != null) bodyBlock.free();
            if (outputBlock != null) outputBlock.free();
        }
    }

    /**
     * 检查输出缓冲区
     */
    private static void checkOutput(Emulator<?> emulator, UnidbgPointer outputPtr, String name) {
        try {
            // 尝试读取字符串
            String str = outputPtr.getString(0);
            if (str != null && str.length() > 0 && str.length() < 1000) {
                System.out.println("    → " + name + " (字符串): " + str.substring(0, Math.min(80, str.length())));
                if (str.length() > 80) {
                    System.out.println("      ... (总长度 " + str.length() + ")");
                }
                return;
            }
        } catch (Exception e) {}

        // 尝试读取二进制数据
        try {
            byte[] bytes = outputPtr.getByteArray(0, 100);
            boolean hasData = false;
            for (byte b : bytes) {
                if (b != 0) {
                    hasData = true;
                    break;
                }
            }

            if (hasData) {
                System.out.println("    → " + name + " (十六进制):");
                Inspector.inspect(bytes, "      ");
            } else {
                System.out.println("    → " + name + ": (空)");
            }
        } catch (Exception e) {
            System.out.println("    → " + name + ": (读取失败)");
        }
    }
}
