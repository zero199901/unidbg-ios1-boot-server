package com.anjia.unidbgserver.service;

import com.anjia.unidbgserver.config.UnidbgProperties;
import com.github.unidbg.worker.Worker;
import com.github.unidbg.worker.WorkerLoan;
import com.github.unidbg.worker.WorkerPool;
import com.github.unidbg.worker.WorkerPoolFactory;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Service("turingWorker")
public class TuringServiceWorker implements Worker {
    private static final Logger log = LoggerFactory.getLogger(TuringServiceWorker.class);

    private UnidbgProperties unidbgProperties;
    private WorkerPool pool;
    private TuringService turingService;

    @Value("${spring.task.execution.pool.core-size:4}")
    int poolSize;

    @Autowired
    public void init(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
    }

    public TuringServiceWorker() {
        pool = WorkerPoolFactory.create(TuringServiceWorker::new, poolSize);
    }

    public TuringServiceWorker(WorkerPool pool) {
        this.pool = pool;
    }

    @Autowired
    public TuringServiceWorker(UnidbgProperties unidbgProperties) {
        this.unidbgProperties = unidbgProperties;
        if (this.unidbgProperties.isAsync()) {
            pool = WorkerPoolFactory.create(() -> new TuringServiceWorker(unidbgProperties.isDynarmic(),
                unidbgProperties.isVerbose(), pool), Math.max(poolSize, 4));
            log.info("Turing 线程池大小: {}", poolSize);
        } else {
            this.turingService = new TuringService(unidbgProperties);
        }
    }

    public TuringServiceWorker(boolean dynarmic, boolean verbose, WorkerPool pool) {
        this.pool = pool;
        this.unidbgProperties = new UnidbgProperties();
        unidbgProperties.setDynarmic(dynarmic);
        unidbgProperties.setVerbose(verbose);
        log.info("Turing worker 启动: dynarmic={}, verbose={}", dynarmic, verbose);
        this.turingService = new TuringService(unidbgProperties);
    }

    @Async
    @SneakyThrows
    public CompletableFuture<String> getArgus(String url, byte[] body) {
        String result;
        long start = System.currentTimeMillis();

        if (this.unidbgProperties.isAsync()) {
            while (true) {
                try (WorkerLoan<TuringServiceWorker> loan = pool.borrow(2, TimeUnit.SECONDS)) {
                    if (loan == null) continue;
                    result = loan.get().doWork(url, body);
                    break;
                }
            }
        } else {
            synchronized (this) {
                result = this.doWork(url, body);
            }
        }

        log.info("Turing argus: {}ms", System.currentTimeMillis() - start);
        return CompletableFuture.completedFuture(result);
    }

    private String doWork(String url, byte[] body) {
        return turingService.getArgus(url, body);
    }

    @SneakyThrows
    @Override
    public void destroy() {
        if (turingService != null) {
            try {
                turingService.destroy();
            } catch (Exception e) {
                log.error("销毁TuringService失败", e);
            }
        }
    }
}
