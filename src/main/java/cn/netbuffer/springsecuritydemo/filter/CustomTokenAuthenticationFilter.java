package cn.netbuffer.springsecuritydemo.filter;

import cn.netbuffer.springsecuritydemo.auth.token.CustomTokenAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.io.IOException;

/**
 * 自定义 Header Token 认证过滤器
 * <p>拦截 POST /your-custom-token-login-path 请求，从 Header 中提取 "token" 字段，
 * 封装为 {@link CustomTokenAuthenticationToken} 交由 {@link org.springframework.security.authentication.AuthenticationManager} 进行认证。</p>
 */
@Slf4j
public class CustomTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public CustomTokenAuthenticationFilter() {
        super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/your-custom-token-login-path"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("====================================custom token auth process============================");
        String token = request.getHeader("token");
        CustomTokenAuthenticationToken customTokenAuthenticationToken = new CustomTokenAuthenticationToken(token, null);
        return super.getAuthenticationManager().authenticate(customTokenAuthenticationToken);
    }

}
