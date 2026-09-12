package cn.netbuffer.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 测试权限测试控制器
 * <p>在安全配置中通过 {@code requestMatchers("/test/**").hasAuthority("test")} 进行 URL 级鉴权，仅拥有 "test" 权限的用户允许访问。</p>
 */
@RestController
@RequestMapping("/test")
public class TestController {

    /**
     * 测试人员专属接口
     *
     * @return 状态字符串 "test"
     */
    @GetMapping
    public String get() {
        return "test";
    }
}
