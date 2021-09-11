package cn.netbuffer.springsecuritydemo.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/app")
public class AppController {

    @GetMapping
    public String get() {
        return "app";
    }

    @PreAuthorize("hasAuthority('admin')")
    @GetMapping("access")
    public String access() {
        return "access";
    }

    @PostMapping("csrf-test")
    public Object csrfTest(@RequestBody Map data) {
        log.debug("RequestContextHolder.currentRequestAttributes()={}", RequestContextHolder.currentRequestAttributes());
        return data;
    }

}
