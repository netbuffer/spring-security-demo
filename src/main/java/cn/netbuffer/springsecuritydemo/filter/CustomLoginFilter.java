package cn.netbuffer.springsecuritydemo.filter;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 自定义 JSON 格式登录过滤器
 * <p>拦截 POST /your-custom-login-path 请求，从请求体中解析 JSON 格式的 username 与 password，
 * 封装为 {@link UsernamePasswordAuthenticationToken} 交给 {@link org.springframework.security.authentication.AuthenticationManager} 进行认证。</p>
 */
@Slf4j
public class CustomLoginFilter extends AbstractAuthenticationProcessingFilter {

    public CustomLoginFilter() {
        super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/your-custom-login-path"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("====================================custom login process============================");
        String body = StreamUtils.copyToString(request.getInputStream(), StandardCharsets.UTF_8);
        JSONObject data = JSON.parseObject(body);
        if (data == null) {
            throw new AuthenticationServiceException("Invalid login request payload");
        }
        log.debug("parse login data={}", data);
        String username = data.getString("username");
        String password = data.getString("password");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(username != null ? username.trim() : "", password != null ? password : "");
        return super.getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);
    }

}
