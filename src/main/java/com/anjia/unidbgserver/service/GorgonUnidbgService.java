package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * unidbg 版 Gorgon 签名服务
 *
 * 通过 unidbg 加载 Grace iOS 二进制，调用真实的签名函数。
 *
 * 要启用此服务，需要先通过静态分析找到签名函数偏移：
 *
 *   1. 用 otool / Ghidra 打开 Grace 二进制
 *   2. 搜索字符串 "x-gorgon"（位于 Grace+0xa67a09c）
 *   3. 找引用该字符串的函数 → 即 Gorgon 头部设置函数
 *   4. 向上找调用链 → 找到签名入口函数
 *   5. 记录入口函数相对 Grace 二进制的偏移
 *   6. 填入 GorgonService.java 的 GORGON_FUNC_OFFSET
 *
 * 运行 scripts/find_gorgon_offset.sh 可辅助分析
 */
public class GorgonUnidbgService {
    private static final Logger log = LoggerFactory.getLogger(GorgonUnidbgService.class);

    private final Emulator<DarwinFileIO> emulator;
    private final com.github.unidbg.Module graceModule;
    private final UnidbgProperties props;
    private final long gorgonFuncOffset;

    // 签名函数的输出缓冲区大小（7个签名头，每个最多256字节）
    private static final int OUTPUT_BUFFER_SIZE = 4096;

    public GorgonUnidbgService(UnidbgProperties props, long gorgonFuncOffset) throws Exception {
        this.props       = props;
        this.gorgonFuncOffset = gorgonFuncOffset;

        File ipaFile = new File(props.getIpaPath());
        if (!ipaFile.exists()) {
            throw new IllegalArgumentException("IPA not found: " + ipaFile.getAbsolutePath());
        }

        File workDir = new File(System.getProperty("java.io.tmpdir"), "unidbg-gorgon");
        workDir.mkdirs();

        IpaLoader64 loader = new IpaLoader64(ipaFile, workDir);
        if (props.isDynarmic()) {
            loader.addBackendFactory(new DynarmicFactory(true));
        }

        LoadedIpa loaded = loader.load(new EmulatorConfigurator() {
            @Override
            public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath,
                                  File rootDir, String bundleIdentifier) {
                MachOLoader mem = (MachOLoader) emulator.getMemory();
                // Gorgon 签名函数可能依赖 ObjC，所以启用 ObjC Runtime
                mem.setObjcRuntime(true);
                mem.setCallInitFunction(false);
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                log.info("Grace loaded for Gorgon signing, base=0x{}",
                    Long.toHexString(executable.base));
            }
        });

        emulator    = loaded.getEmulator();
        graceModule = loaded.getExecutable();

        log.info("GorgonUnidbgService ready, func @ Grace+0x{}",
            Long.toHexString(gorgonFuncOffset));
    }

    /**
     * 生成 Gorgon 签名（unidbg 调用真实 iOS 函数）
     * 若 unidbg 调用失败，由调用方降级到 Java 实现
     */
    public Map<String, String> sign(String url, byte[] body) throws Exception {
        long khronos = System.currentTimeMillis() / 1000;

        byte[] urlBytes  = url.getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = body != null ? body : new byte[0];

        MemoryBlock urlBlock    = null;
        MemoryBlock bodyBlock   = null;
        MemoryBlock outputBlock = null;

        try {
            urlBlock    = emulator.getMemory().malloc(urlBytes.length  + 1, true);
            bodyBlock   = emulator.getMemory().malloc(Math.max(bodyBytes.length, 1), true);
            outputBlock = emulator.getMemory().malloc(OUTPUT_BUFFER_SIZE, true);

            UnidbgPointer urlPtr    = urlBlock.getPointer();
            UnidbgPointer bodyPtr   = bodyBlock.getPointer();
            UnidbgPointer outputPtr = outputBlock.getPointer();

            urlPtr.write(urlBytes);
            urlPtr.setByte(urlBytes.length, (byte) 0);
            if (bodyBytes.length > 0) bodyPtr.write(bodyBytes);

            log.debug("调用 Gorgon 签名函数 @ Grace+0x{}", Long.toHexString(gorgonFuncOffset));

            // 调用签名函数
            // 参数约定（根据最终逆向结果调整）：
            //   arg0 = url string pointer
            //   arg1 = body data pointer
            //   arg2 = body length
            //   arg3 = khronos (timestamp in seconds)
            //   arg4 = output buffer pointer
            //   arg5 = output buffer size
            Number ret = emulator.eFunc(
                graceModule.base + gorgonFuncOffset,
                urlPtr.peer,
                bodyPtr.peer,
                (long) bodyBytes.length,
                khronos,
                outputPtr.peer,
                (long) OUTPUT_BUFFER_SIZE
            );

            int retLen = ret.intValue();
            log.debug("签名函数返回值: {}", retLen);

            if (retLen > 0 && retLen <= OUTPUT_BUFFER_SIZE) {
                byte[] output = outputPtr.getByteArray(0, retLen);
                return parseOutput(output, khronos);
            }

            log.warn("签名函数返回异常值: {}", retLen);
            return null;

        } finally {
            if (urlBlock    != null) urlBlock.free();
            if (bodyBlock   != null) bodyBlock.free();
            if (outputBlock != null) outputBlock.free();
        }
    }

    /**
     * 解析签名函数输出
     * 根据实际函数输出格式调整
     */
    private Map<String, String> parseOutput(byte[] output, long khronos) {
        // 解析输出为签名 Map（根据实际格式实现）
        // 若签名函数输出格式确认，在此实现完整解析
        // 当前：若识别到 x-gorgon 前缀（8404xxxx），提取签名值
        String outputStr = new String(output, StandardCharsets.UTF_8).trim();

        if (outputStr.matches("8404[0-9a-f]{46}.*")) {
            // 看起来像有效 Gorgon 输出
            Map<String, String> result = RealGorgonAlgorithm.generateReal(
                outputStr, null);  // 用 URL 传递输出让算法提取
            result.put("x-gorgon", outputStr.substring(0, 52));
            log.info("✓ unidbg Gorgon: {}", outputStr.substring(0, 16) + "...");
            return result;
        }

        return null;
    }

    public void destroy() throws IOException {
        if (emulator != null) emulator.close();
    }
}
