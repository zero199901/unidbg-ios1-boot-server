package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 基于 iOS unidbg 的真实 Gorgon 签名实现
 *
 * 通过 frida 逆向发现的关键信息：
 * - x-gorgon  @ Grace+0xa67a09c
 * - x-argus   @ Grace+0xa67a0b6
 * - x-ladon   @ Grace+0xa67a0a5
 * - x-ss-stub @ Grace+0xa663eec
 *
 * 关键函数地址（待验证）：
 * - Grace+0x641994  (MD5 热点，可能是签名入口)
 * - Grace+0x3f0ff60 (另一个 MD5 调用点)
 * - Grace+0x3f0e880 (SHA256，可能是 argus/medusa)
 */
public class RealGorgonService {
    private static final Logger log = LoggerFactory.getLogger(RealGorgonService.class);


    // 基于 frida 发现的函数偏移（需要通过实际调用验证）
    private static final long SIGN_FUNC_CANDIDATE_1 = 0x641994L;
    private static final long SIGN_FUNC_CANDIDATE_2 = 0x3f0ff60L;
    private static final long SIGN_FUNC_CANDIDATE_3 = 0x3f0e880L;

    private final Emulator<DarwinFileIO> emulator;
    private final Module graceModule;
    private final UnidbgProperties props;

    @SneakyThrows
    public RealGorgonService(UnidbgProperties unidbgProperties) {
        this.props = unidbgProperties;

        File ipaFile = new File(unidbgProperties.getIpaPath());
        if (!ipaFile.exists()) {
            throw new IllegalArgumentException("ipaPath not found: " + ipaFile.getAbsolutePath());
        }

        File workDir = new File(System.getProperty("java.io.tmpdir"), "unidbg-ios-grace-sign");
        workDir.mkdirs();

        IpaLoader64 loader = new IpaLoader64(ipaFile, workDir);
        if (unidbgProperties.isDynarmic()) {
            loader.addBackendFactory(new DynarmicFactory(true));
        }

        LoadedIpa loaded = loader.load(new EmulatorConfigurator() {
            @Override
            public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath,
                                  File rootDir, String bundleIdentifier) {
                MachOLoader mem = (MachOLoader) emulator.getMemory();
                mem.setObjcRuntime(false);  // 不需要完整 ObjC runtime
                mem.setCallInitFunction(false);
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                log.info("Grace 已加载，基地址: 0x{}", Long.toHexString(executable.base));
            }
        });

        emulator = loaded.getEmulator();
        graceModule = loaded.getExecutable();

        log.info("RealGorgonService 初始化完成");
    }

    /**
     * 生成真实的签名参数
     *
     * @param url 完整 URL
     * @param body 请求体
     * @return 包含 6 个签名参数的 Map
     */
    public Map<String, String> generateSign(String url, byte[] body) {
        long khronos = System.currentTimeMillis() / 1000;

        try {
            // 方案1：尝试直接调用签名函数（需要逆向确定正确的函数签名）
            Map<String, String> result = tryCallSignFunction(url, body, khronos);

            if (result != null && result.containsKey("x-gorgon")) {
                log.info("✓ 使用真实签名函数生成成功");
                return result;
            }

            // 方案2：回退到 Java 实现
            log.warn("真实签名函数调用失败，回退到 Java 实现");
            return GorgonAlgorithm.generate(url, body);

        } catch (Exception e) {
            log.error("签名生成失败: {}", e.getMessage(), e);
            return GorgonAlgorithm.generate(url, body);
        }
    }

    /**
     * 尝试调用 Grace 中的真实签名函数
     *
     * 注意：这需要通过 frida 进一步确定：
     * 1. 正确的函数地址
     * 2. 函数签名（参数类型、返回值）
     * 3. 输入数据格式
     */
    private Map<String, String> tryCallSignFunction(String url, byte[] body, long khronos) {
        MemoryBlock urlBlock = null;
        MemoryBlock bodyBlock = null;
        MemoryBlock outputBlock = null;

        try {
            // 构造输入：URL + body + khronos (参考 frida 抓到的 MD5 输入)
            String path = extractPath(url);
            String query = extractQuery(url);

            // 拼接签名数据
            StringBuilder signDataBuilder = new StringBuilder();
            signDataBuilder.append(path);
            if (!query.isEmpty()) {
                signDataBuilder.append("?").append(query);
            }
            if (body != null && body.length > 0) {
                signDataBuilder.append(new String(body, StandardCharsets.UTF_8));
            }
            signDataBuilder.append(khronos);

            byte[] signData = signDataBuilder.toString().getBytes(StandardCharsets.UTF_8);

            // 分配内存
            urlBlock = emulator.getMemory().malloc(url.length() + 1, true);
            bodyBlock = emulator.getMemory().malloc(Math.max(body != null ? body.length : 0, 1), true);
            outputBlock = emulator.getMemory().malloc(2048, true);  // 足够大的输出缓冲区

            UnidbgPointer urlPtr = urlBlock.getPointer();
            UnidbgPointer bodyPtr = bodyBlock.getPointer();
            UnidbgPointer outputPtr = outputBlock.getPointer();

            urlPtr.setString(0, url);
            if (body != null && body.length > 0) {
                bodyPtr.write(body);
            }

            log.debug("尝试调用签名函数 Grace+0x{}", Long.toHexString(SIGN_FUNC_CANDIDATE_1));

            // TODO: 需要通过 frida 确定正确的函数签名
            // 这里是假设的调用方式，可能需要调整参数
            Number ret = emulator.eFunc(graceModule.base + SIGN_FUNC_CANDIDATE_1,
                urlPtr.peer,
                bodyPtr.peer,
                body != null ? body.length : 0,
                khronos,
                outputPtr.peer);

            log.debug("函数返回值: {}", ret);

            // 尝试从输出缓冲区读取签名
            // TODO: 需要确定输出格式
            String output = outputPtr.getString(0);
            if (output != null && output.length() > 0) {
                log.info("函数输出: {}", output);
                // 解析输出构造结果
                return parseSignOutput(output, khronos);
            }

        } catch (Exception e) {
            log.debug("调用签名函数失败: {}", e.getMessage());
        } finally {
            if (urlBlock != null) urlBlock.free();
            if (bodyBlock != null) bodyBlock.free();
            if (outputBlock != null) outputBlock.free();
        }

        return null;
    }

    private Map<String, String> parseSignOutput(String output, long khronos) {
        // TODO: 根据实际输出格式解析
        Map<String, String> result = new HashMap<>();
        result.put("x-khronos", String.valueOf(khronos));
        // 解析其他签名参数...
        return result;
    }

    private String extractPath(String url) {
        try {
            int schemeEnd = url.indexOf("://");
            if (schemeEnd != -1) url = url.substring(schemeEnd + 3);
            int hostEnd = url.indexOf('/');
            if (hostEnd != -1) url = url.substring(hostEnd);
            int queryStart = url.indexOf('?');
            if (queryStart != -1) return url.substring(0, queryStart);
            return url;
        } catch (Exception e) {
            return "/";
        }
    }

    private String extractQuery(String url) {
        int queryStart = url.indexOf('?');
        if (queryStart != -1 && queryStart < url.length() - 1) {
            return url.substring(queryStart + 1);
        }
        return "";
    }

    public void destroy() throws IOException {
        if (emulator != null) {
            emulator.close();
        }
    }
}
