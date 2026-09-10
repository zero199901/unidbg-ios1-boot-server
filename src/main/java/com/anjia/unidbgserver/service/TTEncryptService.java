package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.context.EditableArm64RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.WrapCallback;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.hook.Substrate;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class TTEncryptService {
    private static final Logger log = LoggerFactory.getLogger(TTEncryptService.class);


    private static final long ENCRYPT_FUNC = 0x1005de758L;

    private final Emulator<DarwinFileIO> emulator;
    private final Module graceModule;
    private final UnidbgProperties props;
    private boolean hookInstalled = false;

    @SneakyThrows
    TTEncryptService(UnidbgProperties unidbgProperties) {
        this.props = unidbgProperties;

        File ipaFile = new File(unidbgProperties.getIpaPath());
        if (!ipaFile.exists()) {
            throw new IllegalArgumentException("ipaPath not found: " + ipaFile.getAbsolutePath());
        }
        File workDir = new File(System.getProperty("java.io.tmpdir"), "unidbg-ios-grace");
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
                mem.setObjcRuntime(false);
                mem.setCallInitFunction(false);
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                log.info("Grace loaded, 将使用 Hook 方案绕过依赖");
            }
        });

        emulator = loaded.getEmulator();
        graceModule = loaded.getExecutable();

        // 安装 hook
        installHooks();

        log.info("Ready with hooks installed");
    }

    private void installHooks() {
        try {
            // Hook 加密库函数，返回我们自己的实现
            IHookZz hookZz = HookZz.getInstance(emulator);

            // Hook sub_10442ADC8 - 第一个被调用的加密库函数
            hookZz.wrap(graceModule.base + 0x442ADC8L, new WrapCallback<EditableArm64RegisterContext>() {
                @Override
                public void preCall(Emulator<?> emulator, EditableArm64RegisterContext ctx, com.github.unidbg.hook.hookzz.HookEntryInfo info) {
                    log.debug("Hook: sub_10442ADC8 called");
                    // 这个函数似乎是复制 IV 的
                    // 我们提供一个固定的 IV
                    long destPtr = ctx.getXLong(0);
                    int size = ctx.getXInt(1);

                    if (size == 16) {
                        // 写入 16 字节零 IV
                        UnidbgPointer dest = UnidbgPointer.pointer(emulator, destPtr);
                        if (dest != null) {
                            byte[] iv = new byte[16];
                            dest.write(iv);
                            log.debug("  -> 提供了 16 字节 IV");
                        }
                    }
                }
            });

            log.info("Hooks installed successfully");
            hookInstalled = true;

        } catch (Exception e) {
            log.warn("Failed to install hooks: {}", e.getMessage());
            // 继续运行，尝试不用 hook
        }
    }

    public byte[] ttEncrypt(String body) {
        byte[] input = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];
        if (props.isVerbose()) Inspector.inspect(input, "ttEncrypt input");

        // 方案 1：尝试调用真实函数（带 hook）
        if (hookInstalled) {
            byte[] result = tryRealEncrypt(input);
            if (result != null && result.length > 0) {
                return result;
            }
        }

        // 方案 2：完全用 Java 实现 AES-256-GCM
        log.info("真实函数失败，使用 Java AES-256-GCM 实现");
        return javaAesGcmEncrypt(input);
    }

    private byte[] tryRealEncrypt(byte[] input) {
        MemoryBlock inputBlock = null;
        MemoryBlock keyBlock = null;
        MemoryBlock outputBlock = null;

        try {
            byte[] key = new byte[32];  // 32 字节零 key
            int outputSize = input.length + 64;

            inputBlock = emulator.getMemory().malloc(Math.max(input.length, 1), true);
            keyBlock = emulator.getMemory().malloc(key.length, true);
            outputBlock = emulator.getMemory().malloc(outputSize, true);

            UnidbgPointer inputPtr = inputBlock.getPointer();
            UnidbgPointer keyPtr = keyBlock.getPointer();
            UnidbgPointer outputPtr = outputBlock.getPointer();

            if (input.length > 0) inputPtr.write(input);
            keyPtr.write(key);

            log.debug("调用加密函数（带 hook）");

            Number ret = emulator.eFunc(ENCRYPT_FUNC,
                outputPtr.peer, (long) outputSize,
                keyPtr.peer,
                inputPtr.peer, (long) input.length);

            int retVal = ret.intValue();
            log.debug("  返回值: {}", retVal);

            if (retVal > 0 && retVal <= outputSize) {
                byte[] encrypted = outputPtr.getByteArray(0, retVal);
                log.info("✓ 加密成功（真实函数）！");
                if (props.isVerbose()) Inspector.inspect(encrypted, "加密输出");
                return encrypted;
            }

        } catch (Exception e) {
            log.debug("真实函数调用失败: {}", e.getMessage());
        } finally {
            if (inputBlock != null) inputBlock.free();
            if (keyBlock != null) keyBlock.free();
            if (outputBlock != null) outputBlock.free();
        }

        return null;
    }

    /**
     * 纯 Java 实现的 AES-256-GCM 加密
     * 输出格式：[2字节头部 0x01BD] + [16字节IV] + [密文+TAG]
     *
     * 注意：这是根据 IDA 分析推断的格式，使用零 key
     * 如果需要与真实豆包兼容，需要：
     * 1. 逆向确定真实的 key 派生方式
     * 2. 确认 IV 是随机生成还是从某处派生
     * 3. 验证输出格式是否完全正确
     */
    private byte[] javaAesGcmEncrypt(byte[] plaintext) {
        try {
            byte[] key = new byte[32];  // 32 字节零 key
            // TODO: 生产环境应该使用真实的 key 派生算法

            byte[] iv = new byte[12];   // GCM 标准使用 12 字节 IV
            new SecureRandom().nextBytes(iv);  // 随机生成 IV（更安全）

            // 使用 Java Crypto API
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);  // 128-bit tag

            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] ciphertext = cipher.doFinal(plaintext);

            // 构造输出格式：[头部2字节] + [IV 12字节] + [4字节填充] + [密文+TAG]
            // 从 IDA 看到 IV 区域是 16 字节，但 GCM 只用 12 字节
            byte[] result = new byte[2 + 16 + ciphertext.length];
            result[0] = 0x01;  // 头部字节 1
            result[1] = (byte) 0xBD;  // 头部字节 2（从 IDA 看到是 445 = 0x01BD）
            System.arraycopy(iv, 0, result, 2, 12);  // 12 字节 IV
            // result[14-17] 保持为 0（填充）
            System.arraycopy(ciphertext, 0, result, 18, ciphertext.length);

            log.info("✓ 加密成功（Java AES-256-GCM）！输出长度: {}", result.length);
            if (props.isVerbose()) {
                Inspector.inspect(result, "Java AES-GCM 输出");
            }

            return result;

        } catch (Exception e) {
            log.error("Java AES-GCM 加密失败: {}", e.getMessage(), e);
            return new byte[0];
        }
    }

    /**
     * 解密 ttEncrypt 输出的 Base64 字节序列。
     * 格式：[2字节头部 0x01BD] + [12字节IV] + [4字节填充] + [密文+16字节GCM TAG]
     */
    public byte[] ttDecrypt(byte[] encrypted) {
        if (encrypted == null || encrypted.length < 18 + 16) {
            throw new IllegalArgumentException("encrypted data too short: " + (encrypted == null ? 0 : encrypted.length));
        }
        if (encrypted[0] != 0x01 || (encrypted[1] & 0xFF) != 0xBD) {
            throw new IllegalArgumentException(String.format("invalid header: %02X%02X", encrypted[0], encrypted[1] & 0xFF));
        }
        try {
            byte[] iv = new byte[12];
            System.arraycopy(encrypted, 2, iv, 0, 12);

            int cipherLen = encrypted.length - 18;
            byte[] ciphertext = new byte[cipherLen];
            System.arraycopy(encrypted, 18, ciphertext, 0, cipherLen);

            byte[] key = new byte[32]; // 与加密保持一致的零 key
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);

            log.info("✓ 解密成功！输出长度: {}", plaintext.length);
            if (props.isVerbose()) Inspector.inspect(plaintext, "ttDecrypt 输出");
            return plaintext;
        } catch (Exception e) {
            log.error("ttDecrypt 失败: {}", e.getMessage(), e);
            throw new RuntimeException("decrypt failed: " + e.getMessage(), e);
        }
    }

    /**
     * 解密 tc 协议格式的数据
     * 格式：[2字节头部 "tc" 0x7463] + [2字节版本 0x0510] + [4字节元数据] + [bvx2 压缩数据]
     *
     * tc 协议使用 Apple libcompression 进行数据压缩
     */
    public byte[] tcDecrypt(byte[] encrypted) {
        if (encrypted == null || encrypted.length < 8) {
            throw new IllegalArgumentException("tc data too short: " + (encrypted == null ? 0 : encrypted.length));
        }

        // 检查 tc 魔术字
        int magic = ((encrypted[0] & 0xFF) << 8) | (encrypted[1] & 0xFF);
        if (magic != 0x7463) {  // "tc"
            throw new IllegalArgumentException(String.format("invalid tc header: 0x%04X (expected 0x7463)", magic));
        }

        // 解析版本
        int version = ((encrypted[2] & 0xFF) << 8) | (encrypted[3] & 0xFF);
        log.debug("tc protocol version: 0x{}", Integer.toHexString(version));

        // 解析元数据（4字节，可能是时间戳或长度）
        long metadata = ((encrypted[4] & 0xFFL) << 24) |
                       ((encrypted[5] & 0xFFL) << 16) |
                       ((encrypted[6] & 0xFFL) << 8) |
                       (encrypted[7] & 0xFFL);
        log.debug("tc metadata: {}", metadata);

        // 提取压缩数据（跳过8字节头部）
        byte[] compressed = new byte[encrypted.length - 8];
        System.arraycopy(encrypted, 8, compressed, 0, compressed.length);

        // 先尝试 libcompression 解压
        try {
            return decompressWithLibcompression(compressed);
        } catch (Exception e) {
            log.warn("libcompression failed, trying Java Inflater: {}", e.getMessage());
            // 回退到 Java 原生解压
            return decompressWithJavaInflater(compressed);
        }
    }

    /**
     * 公共方法：解压 BVX2 格式数据
     *
     * @param bvx2Data BVX2 压缩的数据
     * @return 解压后的数据
     */
    public byte[] decompressBVX2(byte[] bvx2Data) {
        return decompressWithLibcompression(bvx2Data);
    }

    /**
     * 使用 Apple libcompression.dylib 解压数据
     *
     * 从 Frida hook 捕获的信息：
     * - 压缩数据头部是 "bvx2" (0x62767832)
     * - 使用的算法有：LZFSE, LZMA, ZLIB, LZ4, LZBITMAP 等
     * - 算法代码示例：962084864, 962281472, 962330624 等
     */
    private byte[] decompressWithLibcompression(byte[] compressed) {
        MemoryBlock compressedBlock = null;
        MemoryBlock decompressedBlock = null;
        MemoryBlock scratchBlock = null;

        try {
            // 检查是否是 bvx2 格式
            if (compressed.length >= 4) {
                String header = String.format("%c%c%c%c",
                    (char)compressed[0], (char)compressed[1],
                    (char)compressed[2], (char)compressed[3]);
                log.debug("Compression format header: {}", header);
            }

            // 分配内存
            int maxDecompressedSize = compressed.length * 20;  // 预估解压后大小
            compressedBlock = emulator.getMemory().malloc(compressed.length, true);
            decompressedBlock = emulator.getMemory().malloc(maxDecompressedSize, true);

            // 分配 scratch buffer（工作缓冲区），某些压缩算法需要
            int scratchSize = compressed.length * 4;
            scratchBlock = emulator.getMemory().malloc(scratchSize, true);

            UnidbgPointer compressedPtr = compressedBlock.getPointer();
            UnidbgPointer decompressedPtr = decompressedBlock.getPointer();
            UnidbgPointer scratchPtr = scratchBlock.getPointer();

            compressedPtr.write(compressed);

            // 查找 libcompression.dylib
            Module libcompression = emulator.getMemory().findModule("libcompression.dylib");
            if (libcompression == null) {
                // 尝试加载 libcompression
                log.info("Loading libcompression.dylib...");
                MachOLoader loader = (MachOLoader) emulator.getMemory();
                libcompression = loader.dlopen("/usr/lib/libcompression.dylib");
                if (libcompression == null) {
                    throw new RuntimeException("Failed to load libcompression.dylib");
                }
            }

            // 查找 compression_decode_buffer 函数
            // size_t compression_decode_buffer(uint8_t *dst_buffer, size_t dst_size,
            //                                   const uint8_t *src_buffer, size_t src_size,
            //                                   void *scratch_buffer, compression_algorithm algorithm);
            long decodeFunc = libcompression.findSymbolByName("_compression_decode_buffer").getAddress();
            log.debug("compression_decode_buffer at: 0x{}", Long.toHexString(decodeFunc));

            // 尝试不同的压缩算法
            // 从 Apple compression.h：
            // COMPRESSION_LZFSE = 0x801, LZMA = 0x306, ZLIB = 0x205, LZ4 = 0x100, LZBITMAP = 0x702
            // 从 Frida 捕获：ByteDance 使用自定义算法 2049 (0x0801)
            int[] algorithms = {
                2049,   // ByteDance 自定义算法 (从 Frida 捕获)
                0x801,  // COMPRESSION_LZFSE
                0x306,  // COMPRESSION_LZMA
                0x205,  // COMPRESSION_ZLIB
                0x100,  // COMPRESSION_LZ4
                0x702   // COMPRESSION_LZBITMAP
            };

            for (int algorithm : algorithms) {
                try {
                    log.debug("Trying algorithm: 0x{}", Integer.toHexString(algorithm));

                    // 调用 compression_decode_buffer，传入 scratch buffer
                    Number ret = emulator.eFunc(decodeFunc,
                        decompressedPtr.peer, (long) maxDecompressedSize,
                        compressedPtr.peer, (long) compressed.length,
                        scratchPtr.peer,  // scratch_buffer
                        algorithm);

                    int decompressedSize = ret.intValue();
                    log.debug("  Decompressed size: {}", decompressedSize);

                    if (decompressedSize > 0 && decompressedSize <= maxDecompressedSize) {
                        byte[] decompressed = decompressedPtr.getByteArray(0, decompressedSize);
                        log.info("✓ tc 解密成功！算法: 0x{}, 原始大小: {}, 解压后: {}",
                            Integer.toHexString(algorithm), compressed.length, decompressedSize);

                        if (props.isVerbose()) {
                            Inspector.inspect(decompressed, "tc 解压输出");
                        }

                        return decompressed;
                    }

                } catch (Exception e) {
                    log.debug("  Algorithm 0x{} failed: {}", Integer.toHexString(algorithm), e.getMessage());
                }
            }

            throw new RuntimeException("All decompression algorithms failed");

        } catch (Exception e) {
            log.error("tc 解密失败: {}", e.getMessage(), e);
            throw new RuntimeException("tc decrypt failed: " + e.getMessage(), e);
        } finally {
            if (compressedBlock != null) compressedBlock.free();
            if (decompressedBlock != null) decompressedBlock.free();
            if (scratchBlock != null) scratchBlock.free();
        }
    }

    /**
     * 使用 Java 原生 Inflater 解压（回退方案）
     */
    private byte[] decompressWithJavaInflater(byte[] compressed) {
        try {
            java.util.zip.Inflater inflater = new java.util.zip.Inflater(true); // nowrap=true for raw deflate
            inflater.setInput(compressed);

            byte[] buffer = new byte[compressed.length * 10];
            int length = inflater.inflate(buffer);
            inflater.end();

            byte[] result = new byte[length];
            System.arraycopy(buffer, 0, result, 0, length);

            log.info("Java Inflater 解压成功，原始大小: {}, 解压后: {}", compressed.length, length);
            return result;

        } catch (Exception e) {
            log.error("Java Inflater 解压失败", e);
            throw new RuntimeException("Decompression failed", e);
        }
    }

    public void destroy() throws IOException {
        if (emulator != null) {
            emulator.close();
        }
    }
}
