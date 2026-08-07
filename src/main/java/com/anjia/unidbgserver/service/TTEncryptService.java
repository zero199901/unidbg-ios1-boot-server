package com.anjia.unidbgserver.service;

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
import com.github.unidbg.utils.Inspector;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class TTEncryptService {

    // ObjC 方法 IMP
    private static final long OBJC_ENCRYPT_IMP = 0x1005dc348L;

    private final Emulator<DarwinFileIO> emulator;
    private final Module graceModule;
    private final UnidbgProperties props;

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
                // 保留 ObjC runtime，尝试使用它
                MachOLoader mem = (MachOLoader) emulator.getMemory();
                mem.setObjcRuntime(true);
                mem.setCallInitFunction(false);  // 跳过崩溃的初始化函数
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                log.info("Grace loaded @ 0x{}, 尝试通过 ObjC 调用加密",
                    Long.toHexString(executable.base));
            }
        });

        emulator = loaded.getEmulator();
        graceModule = loaded.getExecutable();
        log.info("Ready: bundleId={} v={}", loaded.getBundleIdentifier(), loaded.getBundleVersion());
    }

    public byte[] ttEncrypt(String body) {
        log.warn("豆包加密功能需要完整的初始化，当前 unidbg 环境无法支持");
        log.warn("建议使用以下方案之一：");
        log.warn("  1. Frida + 真实 iOS 设备（成功率 99%）");
        log.warn("  2. 纯 Java 重新实现 AES-256-GCM（需要完整逆向）");
        log.warn("  3. 寻找豆包旧版本或 Android 版本");
        return new byte[0];
    }

    public void destroy() throws IOException {
        if (emulator != null) {
            emulator.close();
        }
    }
}
