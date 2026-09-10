package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.utils.Inspector;
import com.github.unidbg.worker.Worker;
import com.github.unidbg.worker.WorkerLoan;
import com.github.unidbg.worker.WorkerPool;
import com.github.unidbg.worker.WorkerPoolFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service("ttEncryptWorker")
public class TTEncryptServiceWorker implements Worker {
    private static final Logger log = LoggerFactory.getLogger(TTEncryptServiceWorker.class);


    private UnidbgProperties unidbgProperties;
    private WorkerPool pool;
    private TTEncryptService ttEncryptService;
    @Value("${spring.task.execution.pool.core-size:4}")
    int poolSize;

    @Autowired
    public void init(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
    }

    public TTEncryptServiceWorker() {
        pool = WorkerPoolFactory.create(TTEncryptServiceWorker::new, poolSize);
    }

    public TTEncryptServiceWorker(WorkerPool pool) {
        this.pool = pool;
    }

    @Autowired
    public TTEncryptServiceWorker(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
        if (this.unidbgProperties.isAsync()) {
            pool = WorkerPoolFactory.create(() -> new TTEncryptServiceWorker(unidbgProperties.isDynarmic(),
                unidbgProperties.isVerbose(), pool), Math.max(poolSize, 4));
            log.info("线程池为:{}", poolSize);
        } else {
            this.ttEncryptService = new TTEncryptService(unidbgProperties);
        }
    }

    public TTEncryptServiceWorker(boolean dynarmic, boolean verbose, WorkerPool pool) {
        this.pool = pool;
        this.unidbgProperties = new UnidbgProperties();
        unidbgProperties.setDynarmic(dynarmic);
        unidbgProperties.setVerbose(verbose);
        log.info("是否启用动态引擎:{},是否打印详细信息:{}", dynarmic, verbose);
        this.ttEncryptService = new TTEncryptService(unidbgProperties);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<byte[]> ttEncrypt(String key1, String body) {

        byte[] data;
        TTEncryptServiceWorker worker;
        long start = System.currentTimeMillis();
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                try (WorkerLoan<TTEncryptServiceWorker> loan = pool.borrow(2, TimeUnit.SECONDS)) {
                    if (loan == null) {
                        continue;
                    }
                    worker = loan.get();
                    data = worker.doWork(key1, body);
                    break;
                }
            }
        } else {
            synchronized (this) {
                data = this.doWork(key1, body);
            }
        }

        long currentTimeMillis = System.currentTimeMillis();
        Inspector.inspect(data, Thread.currentThread().getName() + ": " + (System.currentTimeMillis() - start) + "ms" + ", " + (System.currentTimeMillis() - currentTimeMillis) + "ms");
        return CompletableFuture.completedFuture(data);
    }

    private byte[] doWork(String key1, String body) {
        return ttEncryptService.ttEncrypt(body);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<byte[]> ttDecrypt(byte[] encrypted) {
        byte[] result = null;
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                try (WorkerLoan<TTEncryptServiceWorker> loan = pool.borrow(2, TimeUnit.SECONDS)) {
                    if (loan == null) continue;
                    result = loan.get().doDecrypt(encrypted);
                    break;
                }
            }
        } else {
            synchronized (this) {
                result = this.doDecrypt(encrypted);
            }
        }
        return CompletableFuture.completedFuture(result);
    }

    private byte[] doDecrypt(byte[] encrypted) {
        return ttEncryptService.ttDecrypt(encrypted);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<byte[]> tcDecrypt(byte[] encrypted) {
        byte[] result = null;
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                try (WorkerLoan<TTEncryptServiceWorker> loan = pool.borrow(2, TimeUnit.SECONDS)) {
                    if (loan == null) continue;
                    result = loan.get().doTcDecrypt(encrypted);
                    break;
                }
            }
        } else {
            synchronized (this) {
                result = this.doTcDecrypt(encrypted);
            }
        }
        return CompletableFuture.completedFuture(result);
    }

    private byte[] doTcDecrypt(byte[] encrypted) {
        return ttEncryptService.tcDecrypt(encrypted);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<byte[]> decompressBVX2(byte[] bvx2Data) {
        byte[] result = null;
        if (this.unidbgProperties.isAsync()) {
            while (true) {
                try (WorkerLoan<TTEncryptServiceWorker> loan = pool.borrow(2, TimeUnit.SECONDS)) {
                    if (loan == null) continue;
                    result = loan.get().doDecompressBVX2(bvx2Data);
                    break;
                }
            }
        } else {
            synchronized (this) {
                result = this.doDecompressBVX2(bvx2Data);
            }
        }
        return CompletableFuture.completedFuture(result);
    }

    private byte[] doDecompressBVX2(byte[] bvx2Data) {
        return ttEncryptService.decompressBVX2(bvx2Data);
    }

    @Override
    public void destroy() {
        try {
            ttEncryptService.destroy();
        } catch (Exception e) {
            log.error("销毁TTEncryptService失败", e);
        }
    }
}
