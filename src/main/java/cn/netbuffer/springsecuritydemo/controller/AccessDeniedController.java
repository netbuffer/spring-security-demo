package cn.netbuffer.springsecuritydemo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * 403 访问被拒绝响应控制器
 * <p>支持 GET/POST 等所有请求方式转发至 /403.html，直接输出 403 页面内容，避免由于 POST 转发到静态资源导致 405 Method Not Allowed。</p>
 */
@RestController
public class AccessDeniedController {

    private static final String FORBIDDEN_HTML = """
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <title>403 Forbidden</title>
            </head>
            <body>
                <h2>403 - 访问被拒绝 (Access Denied)</h2>
                <p>您没有权限访问该资源或 CSRF 验证失败。</p>
                <p><a href="/login.html">返回登录页</a> | <a href="/info">返回公共信息页</a></p>
            </body>
            </html>
            """;

    @RequestMapping(value = "/403.html", produces = MediaType.TEXT_HTML_VALUE)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public String accessDenied() {
        return FORBIDDEN_HTML;
    }
}
