package ee.eesti.authentication.controller;

import ee.eesti.authentication.service.WhiteListService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import rig.commons.aop.Timed;

import java.sql.Timestamp;

import static java.time.LocalDateTime.now;

@CrossOrigin(originPatterns = "*", allowCredentials = "true")
@RestController
@RequestMapping("/sessionkey")
@Slf4j
@Timed
public class SessionKeyController {

    private final WhiteListService allowList;

    private static final ResponseEntity<?> emptyOkResponse = ResponseEntity.ok().build();
    private static final ResponseEntity<?> emptyNotFoundResponse = ResponseEntity.notFound().build();

    public SessionKeyController(WhiteListService allowList) {
        this.allowList = allowList;
    }

    @Value("${sessionkey.whitelist.period:30}")
    private Long sessionKeyTimeout;

    @PostMapping("/add")
    public ResponseEntity<?> addSessionKey(@RequestBody String sessionKey, HttpServletResponse response) {
        boolean success = allowList.addSessionToAllowlist(sessionKey, Timestamp.valueOf(now().plusMinutes(sessionKeyTimeout)));
        if (!success) {
            log.error("Failed to add session key '%s'".formatted(sessionKey));
        }
        return emptyOkResponse;
    }

    @PostMapping("/check")
    public ResponseEntity<?> checkSessionKey(@RequestBody String sessionKey, HttpServletResponse response) {
        if (allowList.checkWhitelisted(sessionKey))
            return emptyOkResponse;
        else
            return emptyNotFoundResponse;
    }
}
