package com.anjia.unidbgserver.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

public class PrintUtils {
    private static final Logger log = LoggerFactory.getLogger(PrintUtils.class);


    public static void printFileResolve(String pathname) {
        printFileResolve(pathname, null);
    }

    public static void printFileResolve(String pathname, String localPathName) {
        String builder = "\n" + "            case \"" + pathname + "\": {\n" +
                "                return FileResult.success(new SimpleFileIO(oflags, TempFileUtils.getTempFile(\""
                + StringUtils.defaultString(localPathName) + "\"), pathname));\n" +
                "            }";
        log.debug(builder);
    }
}
