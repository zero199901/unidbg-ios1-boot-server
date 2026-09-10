package com.anjia.unidbgserver.web;

import com.anjia.unidbgserver.service.TuringServiceWorker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping(path = "/api/turing", produces = MediaType.APPLICATION_JSON_VALUE)
public class TuringController {
    private static final Logger log = LoggerFactory.getLogger(TuringController.class);

    @Resource(name = "turingWorker")
    private TuringServiceWorker turingServiceWorker;

    /**
     * POST /api/turing/argus?url=xxx
     * body: raw request body bytes
     * returns: x-argus header value as plain string
     */
    @PostMapping(value = "argus", consumes = MediaType.TEXT_PLAIN_VALUE)
    public String argus(
        @RequestParam String url,
        @RequestBody(required = false) String body
    ) throws Exception {
        byte[] bodyBytes = body != null ? body.getBytes(StandardCharsets.UTF_8) : new byte[0];
        String argus = turingServiceWorker.getArgus(url, bodyBytes).get();
        log.info("argus: url={}, body.len={}, argus.len={}",
            url.length() > 60 ? url.substring(0, 60) + "..." : url,
            bodyBytes.length,
            argus != null ? argus.length() : -1);
        return argus != null ? argus : "";
    }

    /**
     * GET /api/turing/argus?url=xxx&body=xxx  (quick test)
     */
    @GetMapping(value = "argus")
    public String argusGet(
        @RequestParam String url,
        @RequestParam(required = false, defaultValue = "") String body
    ) throws Exception {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String argus = turingServiceWorker.getArgus(url, bodyBytes).get();
        return argus != null ? argus : "";
    }
}
