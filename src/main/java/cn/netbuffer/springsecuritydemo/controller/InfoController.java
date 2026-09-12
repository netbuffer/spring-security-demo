package cn.netbuffer.springsecuritydemo.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 公开信息控制器
 * <p>该控制器下的路径在 Spring Security 配置中放行 (permitAll)，无需认证即可访问。</p>
 */
@RestController
@RequestMapping("/info")
public class InfoController {

    @Value("${spring.application.name:spring-security-demo}")
    private String appName;

    /**
     * 获取基础信息接口（公开）
     *
     * @return 静态字符串 "info"
     */
    @GetMapping
    public String get() {
        return "info";
    }

    /**
     * 获取应用名称（公开）
     *
     * @return 应用配置的名称
     */
    @GetMapping("appName")
    public String appName() {
        return appName;
    }
}
