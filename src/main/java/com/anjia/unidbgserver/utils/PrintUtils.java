package com.anjia.unidbgserver.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class PrintUtils {

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
