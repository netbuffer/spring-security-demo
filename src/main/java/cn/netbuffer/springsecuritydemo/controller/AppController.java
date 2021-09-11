package cn.netbuffer.springsecuritydemo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

}
