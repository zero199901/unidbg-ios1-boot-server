package com.anjia.unidbgserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * unidbg配置类
 *
 * @author AnJia
 * @since 2021-07-26 19:13
 */
@ConfigurationProperties(prefix = "application.unidbg")
public class UnidbgProperties {
    /**
     * 是否使用 DynarmicFactory
     */
    boolean dynarmic;
    /**
     * 是否打印调用信息
     */
    boolean verbose;

    /**
     * 是否使用异步多线程
     */
    boolean async = true;

    /**
     * IPA 文件的绝对路径
     */
    String ipaPath;

    // Getters and Setters
    public boolean isDynarmic() {
        return dynarmic;
    }

    public void setDynarmic(boolean dynarmic) {
        this.dynarmic = dynarmic;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public boolean isAsync() {
        return async;
    }

    public void setAsync(boolean async) {
        this.async = async;
    }

    public String getIpaPath() {
        return ipaPath;
    }

    public void setIpaPath(String ipaPath) {
        this.ipaPath = ipaPath;
    }
}
