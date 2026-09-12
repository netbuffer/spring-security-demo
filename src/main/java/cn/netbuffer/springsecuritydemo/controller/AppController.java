package cn.netbuffer.springsecuritydemo.controller;

import cn.netbuffer.springsecuritydemo.pojo.DataObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Map;

/**
 * 业务与高级安全特性测试控制器
 * <p>涵盖已认证基础访问、方法级前置鉴权 ({@code @PreAuthorize})、方法级后置鉴权 ({@code @PostAuthorize})、
 * 自定义权限评估 ({@code hasPermission}) 以及 CSRF 防护测试等。</p>
 */
@Slf4j
@RestController
@RequestMapping("/app")
public class AppController {

    /**
     * 基础登录后访问接口
     * <p>匹配 {@code anyRequest().authenticated()}，任意有效登录用户均可访问。</p>
     *
     * @return 响应 "app"
     */
    @GetMapping
    public String get() {
        return "app";
    }

    /**
     * 当前登录用户信息接口
     *
     * @param authentication 当前认证对象
     * @return 当前用户名及权限信息
     */
    @GetMapping("me")
    public Object me(org.springframework.security.core.Authentication authentication) {
        if (authentication == null) {
            return Map.of("authenticated", false);
        }
        return Map.of(
                "authenticated", authentication.isAuthenticated(),
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities().stream().map(Object::toString).toList()
        );
    }

    /**
     * 方法级鉴权测试接口（需要 admin 权限）
     *
     * @return 响应 "access"
     */
    @PreAuthorize("hasAuthority('admin')")
    @GetMapping("access")
    public String access() {
        return "access";
    }

    /**
     * 方法级后置鉴权测试接口
     * <p>在目标方法执行完成后校验返回值中的 owner 属性是否与当前登录用户的 username 一致，一致则返回，否则返回 403 Forbidden。</p>
     *
     * @param owner 资源归属用户名
     * @return DataObject 对象
     */
    @PostAuthorize("returnObject.owner == principal.username")
    @GetMapping("resource")
    public DataObject resource(String owner) {
        log.debug("resource get principal={}", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        DataObject dataObject = new DataObject();
        dataObject.setOwner(owner);
        return dataObject;
    }

    /**
     * 细粒度权限校验：校验当前用户对资源 target-id 是否拥有 read 权限
     *
     * @return 校验通过返回 "ok"
     */
    @GetMapping("resource/target-id/read")
    @PreAuthorize("hasPermission('target-id','read')")
    public String resourceHasPermissionRead() {
        return "ok";
    }

    /**
     * 细粒度权限校验：校验当前用户对资源 target-id 是否拥有 write 权限
     *
     * @return 校验通过返回 "ok"
     */
    @GetMapping("resource/target-id/write")
    @PreAuthorize("hasPermission('target-id','write')")
    public String resourceHasPermissionWrite() {
        return "ok";
    }

    /**
     * CSRF 校验测试接口
     * <p>客户端在发起 POST 请求时必须携带有效的 CSRF Token（通过 Cookie 与 Header 或请求参数传递），否则将被拒绝。</p>
     *
     * @param data 请求体 JSON 映射
     * @return 原样回传提交的数据
     */
    @PostMapping("csrf-test")
    public Object csrfTest(@RequestBody Map data) {
        log.debug("RequestContextHolder.currentRequestAttributes()={}", RequestContextHolder.currentRequestAttributes());
        return data;
    }

}
