package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
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

/**
 * iOS Grace (doubao) unidbg 服务。
 *
 * 关键修复：unidbg-ios-0.9.9-bootstrap-fix.jar
 *   MachOLoader.java line 368: loadInternal(url, false→true, false)
 *   让 bootstrap_objc 的 __mod_init_func 正常执行，
 *   初始化 ObjC 全局 hash table，修复 GetClassHook null deref。
 *
 * 调用链：
 *   setObjcRuntime(true) + setCallInitFunction(false)
 *   → bootstrap 初始化 → libobjc 初始化 → _dyld_objc_notify_register 设置
 *   → Grace 类注册 → objc_getClass("BDTGAES256GCM") 可用
 *   → +[BDTGAES256GCM encryptData:key:error:] IMP=0x1005dc348
 */
@Slf4j
public class TTEncryptService {

    private final Emulator<DarwinFileIO> emulator;
    private final Module graceModule;
    private final UnidbgProperties props;

    // libobjc C 符号（绕开 JNA ObjcClass 结构体读取 bug）
    private Symbol objc_getClass;
    private Symbol sel_registerName;
    private Symbol objc_msgSend;

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
        loader.setForceCallInit(true); // 强制系统库初始化（libobjc 等）
        if (unidbgProperties.isDynarmic()) {
            loader.addBackendFactory(new DynarmicFactory(true));
        }

        LoadedIpa loaded = loader.load(new EmulatorConfigurator() {
            @Override
            public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath,
                                  File rootDir, String bundleIdentifier) {
                MachOLoader mem = (MachOLoader) emulator.getMemory();
                // bootstrap_objc 的 forceCallInit 已在 patched jar 里改为 true
                // 系统库 init 由 loader.setForceCallInit(true) 触发
                // Grace 是 payload module，在 loadInternal 里被 isPayloadModule 跳过
                mem.setObjcRuntime(true);
                // callInitFunction 保持 false（由 forceCallInit 参数控制系统库 init）
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                MachOLoader mem = (MachOLoader) emulator.getMemory();
                // 阻止 Grace 的 __init_func 执行
                mem.setCallInitFunction(false);

                // 如果 bootstrap 正常初始化，_objcNotifyMapped 现在应该已被设置
                // 用反射重新触发 Grace 的类注册
                try {
                    java.lang.reflect.Field f = mem.getClass().getDeclaredField("_objcNotifyMapped");
                    f.setAccessible(true);
                    UnidbgPointer notify = (UnidbgPointer) f.get(mem);
                    if (notify != null) {
                        java.lang.reflect.Method m2 = executable.getClass()
                                .getDeclaredMethod("callObjcNotifyMapped", UnidbgPointer.class);
                        m2.setAccessible(true);
                        m2.invoke(executable, notify);
                        log.info("Grace classes registered: notify=0x{}", Long.toHexString(notify.peer));
                    } else {
                        log.warn("_objcNotifyMapped still null — bootstrap patch may not have taken effect");
                    }
                } catch (Exception e) {
                    log.warn("callObjcNotifyMapped failed: {}", e.getMessage());
                }

                // 解析 libobjc C 符号
                Module libobjc = mem.findModule("libobjc.A.dylib");
                if (libobjc != null) {
                    objc_getClass    = libobjc.findSymbolByName("_objc_getClass");
                    sel_registerName = libobjc.findSymbolByName("_sel_registerName");
                    objc_msgSend     = libobjc.findSymbolByName("_objc_msgSend");
                    log.info("libobjc symbols: getClass= selReg={} msgSend={}",
                            objc_getClass != null, sel_registerName != null, objc_msgSend != null);
                }
                log.info("onExecutableLoaded: base=0x{}", Long.toHexString(executable.base));
            }
        });

        emulator = loaded.getEmulator();
        graceModule = loaded.getExecutable();
        log.info("Grace loaded: bundleId={} v={}", loaded.getBundleIdentifier(), loaded.getBundleVersion());
    }

    public byte[] ttEncrypt(String body) {
        byte[] input = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];
        if (props.isVerbose()) Inspector.inspect(input, "ttEncrypt input");

        if (objc_getClass == null || sel_registerName == null || objc_msgSend == null) {
            log.warn("libobjc symbols not available");
            return new byte[0];
        }

        // 1. 获取 BDTGAES256GCM 类
        Number bdtgNum = objc_getClass.call(emulator, "BDTGAES256GCM");
        long bdtgClass = bdtgNum.longValue();
        if (bdtgClass == 0L || bdtgClass == -1L) {
            log.warn("BDTGAES256GCM not found (0x{})", Long.toHexString(bdtgClass));
            return new byte[0];
        }
        log.info("BDTGAES256GCM=0x{}", Long.toHexString(bdtgClass));

        // 2. 获取 NSData 类
        Number nsDataNum = objc_getClass.call(emulator, "NSData");
        long nsDataClass = nsDataNum.longValue();
        if (nsDataClass == 0L || nsDataClass == -1L) {
            log.warn("NSData not found");
            return new byte[0];
        }

        // 3. 注册 selectors
        Number selDwbl    = sel_registerName.call(emulator, "dataWithBytes:length:");
        Number selEncrypt = sel_registerName.call(emulator, "encryptData:key:error:");
        Number selLength  = sel_registerName.call(emulator, "length");
        Number selBytes   = sel_registerName.call(emulator, "bytes");

        byte[] keyBytes = new byte[32]; // AES-256 全零 key（替换为实际 key）
        MemoryBlock inputBlock = emulator.getMemory().malloc(Math.max(input.length, 1), true);
        MemoryBlock keyBlock   = emulator.getMemory().malloc(keyBytes.length, true);
        try {
            UnidbgPointer inputPtr = inputBlock.getPointer();
            UnidbgPointer keyPtr   = keyBlock.getPointer();
            if (input.length > 0) inputPtr.write(input);
            keyPtr.write(keyBytes);

            // 4. 创建 NSData
            Number nsInput = objc_msgSend.call(emulator,
                    nsDataClass, selDwbl.longValue(), inputPtr.peer, (long) input.length);
            Number nsKey = objc_msgSend.call(emulator,
                    nsDataClass, selDwbl.longValue(), keyPtr.peer, (long) keyBytes.length);

            if (nsInput.longValue() == 0L || nsKey.longValue() == 0L) {
                log.warn("NSData creation failed");
                return new byte[0];
            }

            // 5. +[BDTGAES256GCM encryptData:key:error:]
            Number resultObj;
            try {
                resultObj = objc_msgSend.call(emulator,
                        bdtgClass, selEncrypt.longValue(),
                        nsInput.longValue(), nsKey.longValue(), 0L);
            } catch (RuntimeException e) {
                log.warn("encryptData failed: {}", e.getMessage());
                return new byte[0];
            }

            long result = resultObj.longValue();
            if (result == 0L || result == -1L) {
                log.warn("encryptData returned nil");
                return new byte[0];
            }

            // 6. 提取结果字节
            Number lenNum = objc_msgSend.call(emulator, result, selLength.longValue());
            int length = lenNum.intValue();
            if (length <= 0 || length > 65536) {
                log.warn("unexpected length: {}", length);
                return new byte[0];
            }
            Number bytesPtr = objc_msgSend.call(emulator, result, selBytes.longValue());
            return emulator.getMemory().pointer(bytesPtr.longValue()).getByteArray(0, length);

        } catch (RuntimeException e) {
            log.warn("ttEncrypt error: {}", e.getMessage());
            return new byte[0];
        } finally {
            inputBlock.free();
            keyBlock.free();
        }
    }

    public void destroy() throws IOException {
        emulator.close();
        if (props.isVerbose()) log.info("destroy");
    }
}
