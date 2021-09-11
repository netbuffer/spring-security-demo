package cn.netbuffer.springsecuritydemo.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/info")
public class InfoController {

    @Value("${spring.application.name}")
    private String appName;

    @GetMapping
    public String get() {
        return "info";
    }

    @GetMapping("appName")
    public String appName() {
        return appName;
    }
}
