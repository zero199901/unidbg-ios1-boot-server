package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.ios.MachOLoader;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.ipa.EmulatorConfigurator;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.ipa.LoadedIpa;
import com.github.unidbg.ios.objc.NSData;
import com.github.unidbg.ios.objc.NSString;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Calls [BDTuring getSignatureWithUrl:body:] via unidbg ObjC runtime
 * to generate a fresh x-argus token bound to the current device state.
 *
 * Fixed: Changed from BDTuringVerifyService to BDTuring (correct class name from IPA analysis)
 */
public class TuringService {
    private static final Logger log = LoggerFactory.getLogger(TuringService.class);

    private static final String TURING_CLASS = "BDTuring";
    private static final String TURING_SEL   = "getSignatureWithUrl:body:";

    private final Emulator<DarwinFileIO> emulator;
    private final UnidbgProperties props;

    @SneakyThrows
    TuringService(UnidbgProperties props) {
        this.props = props;

        File ipaFile = new File(props.getIpaPath());
        if (!ipaFile.exists()) {
            throw new IllegalArgumentException("IPA not found: " + ipaFile.getAbsolutePath());
        }

        File workDir = new File(System.getProperty("java.io.tmpdir"), "unidbg-turing");
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
                mem.setObjcRuntime(true);
                mem.setCallInitFunction(false);
            }

            @Override
            public void onExecutableLoaded(Emulator<DarwinFileIO> emulator, MachOModule executable) {
                log.info("Grace loaded for Turing argus generation, base=0x{}",
                    Long.toHexString(executable.base));
            }
        });

        emulator = loaded.getEmulator();
        log.info("TuringService ready");
    }

    /**
     * Generates x-argus for the given URL and request body.
     *
     * @param url      full request URL including query parameters
     * @param body     request body bytes (may be empty)
     * @return x-argus header value, or null on failure
     */
    public String getArgus(String url, byte[] body) {
        if (body == null) body = new byte[0];

        try {
            ObjC objc = ObjC.getInstance(emulator);

            ObjcClass cls = objc.getClass(TURING_CLASS);
            if (cls == null) {
                log.error("{} class not found in ObjC runtime", TURING_CLASS);
                return null;
            }

            ObjcObject alloc    = cls.callObjc("alloc");
            ObjcObject instance = alloc.callObjc("init");

            NSString urlNS  = objc.newString(url);
            NSData   bodyNS = objc.newData(body);

            ObjcObject result = instance.callObjc(TURING_SEL, urlNS, bodyNS);
            if (result == null) {
                log.warn("getSignatureWithUrl:body: returned null");
                return null;
            }

            String argus = result.toNSString().toString();
            log.info("✓ argus generated, len={}", argus != null ? argus.length() : 0);
            return argus;

        } catch (Exception e) {
            log.error("Failed to generate argus: {}", e.getMessage(), e);
            return null;
        }
    }

    public void destroy() throws IOException {
        if (emulator != null) emulator.close();
    }
}
