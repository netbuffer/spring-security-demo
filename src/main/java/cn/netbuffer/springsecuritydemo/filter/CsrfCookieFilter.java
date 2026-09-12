package cn.netbuffer.springsecuritydemo.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * CSRF Token Cookie 下发过滤器
 * <p>Spring Security 默认采用 DeferredCsrfToken 懒加载模式，静态页面或未直接使用 CsrfToken 的请求不会主动向客户端写出 CSRF Cookie。
 * 本过滤器在每次请求中解析 request 中的 {@link CsrfToken}，促使其持久化到 Cookie 中（如 csrf-token），以便前端脚本读取。</p>
 */
public class CsrfCookieFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        if (csrfToken != null) {
            // 调用 getToken() 触发 RepositoryDeferredCsrfToken 的 init()，从而生成并写入 Cookie
            csrfToken.getToken();
        }
        filterChain.doFilter(request, response);
    }
}
