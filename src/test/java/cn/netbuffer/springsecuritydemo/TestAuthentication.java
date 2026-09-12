package cn.netbuffer.springsecuritydemo;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Spring Security 认证及加密单元测试
 */
public class TestAuthentication {

    @Test
    @DisplayName("测试手动创建并设置 SecurityContext")
    public void testCreateAuthentication() {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication =
                new TestingAuthenticationToken("username", "password", "ROLE_USER");
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("测试 BCrypt 密码编码与匹配")
    public void testHashPassword() {
        UserDetails user = User.withUsername("user")
                .password("{noop}password")
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password("{noop}password")
                .roles("USER", "ADMIN")
                .build();
        System.out.println("user password=" + user.getPassword());
        System.out.println("admin password=" + admin.getPassword());

        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);
        String result = encoder.encode("myPassword");
        System.out.println("result=" + result);
        assertTrue(encoder.matches("myPassword", result));
    }

}
