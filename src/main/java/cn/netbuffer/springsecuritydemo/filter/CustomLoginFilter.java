package cn.netbuffer.springsecuritydemo.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.Charset;

@Slf4j
public class CustomLoginFilter extends AbstractAuthenticationProcessingFilter {

    public CustomLoginFilter() {
        super(new AntPathRequestMatcher("/your-custom-login-path", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("====================================custom login process============================");
        String body = StreamUtils.copyToString(request.getInputStream(), Charset.forName("UTF-8"));
        JSONObject data = JSON.parseObject(body);
        log.debug("parse login data={}", data);
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(data.getString("username"), data.getString("password"));
        return super.getAuthenticationManager().authenticate(authRequest);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal();
        log.debug("process [{}] login response", user.getUsername());
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        JSONObject data = new JSONObject();
        data.put("user", user.getUsername());
        data.put("session", request.getSession().getId());
        response.getWriter().write(data.toJSONString());
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        log.debug("login fail {}", failed.getMessage());
        response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        JSONObject data = new JSONObject();
        data.put("msg", failed.getMessage());
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write(data.toJSONString());
    }
}
