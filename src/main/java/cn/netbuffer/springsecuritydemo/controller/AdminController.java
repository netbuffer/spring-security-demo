package cn.netbuffer.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 管理员权限测试控制器
 * <p>在安全配置中通过 {@code requestMatchers("/admin/**").hasAuthority("admin")} 进行 URL 级鉴权，仅拥有 "admin" 权限的用户允许访问。</p>
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    /**
     * 管理员专属接口
     *
     * @return 状态字符串 "admin"
     */
    @GetMapping
    public String get() {
        return "admin";
    }
}
