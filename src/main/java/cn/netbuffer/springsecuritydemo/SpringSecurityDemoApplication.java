package cn.netbuffer.springsecuritydemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Spring Security 演示工程启动类
 * <p>开启 Spring Boot 自动配置，并通过 {@link EnableMethodSecurity} 启用方法级安全鉴权。</p>
 */
@SpringBootApplication
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SpringSecurityDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityDemoApplication.class, args);
    }

}
