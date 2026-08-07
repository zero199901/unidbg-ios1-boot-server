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
        // Don't force init — let it run naturally but some may fail
        if (unidbgProperties.isDynarmic()) {
            loader.addBackendFactory(new DynarmicFactory(true));
        }

        LoadedIpa loaded = loader.load(new EmulatorConfigurator() {
            @Override
            public void configure(Emulator<DarwinFileIO> emulator, String executableBundlePath,
                                  File rootDir, String bundleIdentifier) {
                MachOLoader mem = (MachOLoader) emulator.getMemory();
                // Don't load bootstrap_objc — we'll use direct addresses
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                MachOLoader mem = (MachOLoader) emulator.getMemory();

                Module libobjc = mem.findModule("libobjc.A.dylib");
                if (libobjc != null) {
                    objc_getClass    = libobjc.findSymbolByName("_objc_getClass");
                    sel_registerName = libobjc.findSymbolByName("_sel_registerName");
                    objc_msgSend     = libobjc.findSymbolByName("_objc_msgSend");

                    // Use HookZz to replace objc_msgSend and handle NSData methods
                    HookZz hook = HookZz.getInstance(emulator);
                    hook.replace(objc_msgSend.getAddress(), new ReplaceCallback() {
                        @Override
                        public void processArgs(Emulator<?> emulator, long trampoline, Object... context) {
                            // Args: x0=receiver, x1=selector, x2+...=method args
                        }
                    }, null);
                }

                log.info("Grace loaded @ 0x{}", Long.toHexString(executable.base));
            }
        });

        emulator = loaded.getEmulator();
        graceModule = loaded.getExecutable();
        log.info("Ready: bundleId={} v={}", loaded.getBundleIdentifier(), loaded.getBundleVersion());
    }

    public byte[] ttEncrypt(String body) {
        byte[] input = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];
        if (props.isVerbose()) Inspector.inspect(input, "ttEncrypt input");

        if (sel_registerName == null || objc_msgSend == null || objc_getClass == null) {
            log.warn("ObjC runtime not ready");
            return new byte[0];
        }

        // Get NSData class and create real NSData objects via objc_msgSend
        Number nsDataClassNum = objc_getClass.call(emulator, "NSData");
        long nsDataClass = nsDataClassNum.longValue();
        if (nsDataClass == 0L) {
            log.warn("NSData class not found");
            return new byte[0];
        }

        Number selDwbl = sel_registerName.call(emulator, "dataWithBytes:length:");
        Number selEncrypt = sel_registerName.call(emulator, "encryptData:key:error:");
        Number selLength = sel_registerName.call(emulator, "length");
        Number selBytes = sel_registerName.call(emulator, "bytes");

        byte[] keyBytes = new byte[32];
        MemoryBlock inputBlock = emulator.getMemory().malloc(Math.max(input.length, 1), true);
        MemoryBlock keyBlock   = emulator.getMemory().malloc(keyBytes.length, true);
        try {
            UnidbgPointer inputPtr = inputBlock.getPointer();
            UnidbgPointer keyPtr   = keyBlock.getPointer();
            if (input.length > 0) inputPtr.write(input);
            keyPtr.write(keyBytes);

            // Create NSData objects (may be _NSInlineData internally)
            Number nsInput = objc_msgSend.call(emulator, nsDataClass, selDwbl.longValue(),
                    inputPtr.peer, (long) input.length);
            Number nsKey = objc_msgSend.call(emulator, nsDataClass, selDwbl.longValue(),
                    keyPtr.peer, (long) keyBytes.length);
            if (nsInput.longValue() == 0L || nsKey.longValue() == 0L) {
                log.warn("NSData creation failed");
                return new byte[0];
            }

            // Call class method using objc_msgSend (not eFunc on IMP)
            // For class method: objc_msgSend(class, selector, args...)
            Number result;
            try {
                result = objc_msgSend.call(emulator, BDTGAES256GCM_CLASS, selEncrypt.longValue(),
                        nsInput.longValue(), nsKey.longValue(), 0L);
            } catch (RuntimeException e) {
                log.warn("encryptData call failed: {}", e.getMessage());
                return new byte[0];
            }

            long rp = result.longValue();
            if (rp == 0L || rp == -1L) {
                log.warn("encryptData returned nil");
                return new byte[0];
            }

            // Extract result using objc_msgSend to call length/bytes
            Number len = objc_msgSend.call(emulator, rp, selLength.longValue());
            int length = len.intValue();
            if (length <= 0 || length > 65536) {
                log.warn("bad result length {}", length);
                return new byte[0];
            }

            Number bp = objc_msgSend.call(emulator, rp, selBytes.longValue());
            long bytesAddr = bp.longValue();
            if (bytesAddr == 0L) {
                log.warn("bytes returned null");
                return new byte[0];
            }

            return emulator.getMemory().pointer(bytesAddr).getByteArray(0, length);

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
    }
}
