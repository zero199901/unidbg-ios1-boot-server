package com.anjia.unidbgserver.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.anjia.unidbgserver.config.UnidbgProperties;
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

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service("gorgonWorker")
public class GorgonServiceWorker implements Worker {
    private static final Logger log = LoggerFactory.getLogger(GorgonServiceWorker.class);


    private UnidbgProperties unidbgProperties;
    private WorkerPool pool;
    private GorgonService gorgonService;

    @Value("${spring.task.execution.pool.core-size:4}")
    int poolSize;

    @Autowired
    public void init(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
    }

    public GorgonServiceWorker() {
        pool = WorkerPoolFactory.create(GorgonServiceWorker::new, poolSize);
    }

    public GorgonServiceWorker(WorkerPool pool) {
        this.pool = pool;
    }

    @Autowired
    public GorgonServiceWorker(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
        if (this.unidbgProperties.isAsync()) {
            pool = WorkerPoolFactory.create(() -> new GorgonServiceWorker(unidbgProperties.isDynarmic(),
                unidbgProperties.isVerbose(), pool), Math.max(poolSize, 4));
            log.info("Gorgon 线程池大小: {}", poolSize);
        } else {
            this.gorgonService = new GorgonService(unidbgProperties);
        }
    }

    public GorgonServiceWorker(boolean dynarmic, boolean verbose, WorkerPool pool) {
        this.pool = pool;
        this.unidbgProperties = new UnidbgProperties();
        unidbgProperties.setDynarmic(dynarmic);
        unidbgProperties.setVerbose(verbose);
        log.info("Gorgon worker 启动: dynarmic={}, verbose={}", dynarmic, verbose);
        this.gorgonService = new GorgonService(unidbgProperties);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<Map<String, String>> getGorgon(String url, byte[] body) {
        return getGorgon(url, body, null);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<Map<String, String>> getGorgon(String url, byte[] body, String cookie) {
        Map<String, String> headers;
        GorgonServiceWorker worker;
        long start = System.currentTimeMillis();

        if (this.unidbgProperties.isAsync()) {
            while (true) {
                try (WorkerLoan<GorgonServiceWorker> loan = pool.borrow(2, TimeUnit.SECONDS)) {
                    if (loan == null) {
                        continue;
                    }
                    worker = loan.get();
                    headers = worker.doWork(url, body, cookie);
                    break;
                }
            }
        } else {
            synchronized (this) {
                headers = this.doWork(url, body, cookie);
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        log.info("Gorgon 签名完成: {}ms, flag={}", elapsed, cookie != null ? "c0" : "80");
        return CompletableFuture.completedFuture(headers);
    }

    private Map<String, String> doWork(String url, byte[] body, String cookie) {
        return gorgonService.getGorgon(url, body, cookie);
    }

    @SneakyThrows
    @Override
    public void destroy() {
        if (gorgonService != null) {
            try {
                gorgonService.destroy();
            } catch (Exception e) {
                log.error("销毁GorgonService失败", e);
            }
        }
    }
}
