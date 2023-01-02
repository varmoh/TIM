package ee.eesti.authentication.controller;

import ee.eesti.authentication.dao.HeartBeatInfo;
import ee.eesti.authentication.service.HeartBeatService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@Slf4j
@RestController
public class HeartBeatController {

    public static final String URL = "/healthz";

    private final HeartBeatService heartBeatService;

    public HeartBeatController(HeartBeatService heartBeatService) {
        this.heartBeatService = heartBeatService;
    }

    @RequestMapping(value = HeartBeatController.URL)
    public ResponseEntity<HeartBeatInfo> getData() {
        return ResponseEntity.ok().body(heartBeatService.getData());
    }

}
