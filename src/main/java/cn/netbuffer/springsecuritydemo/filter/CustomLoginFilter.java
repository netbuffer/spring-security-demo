package cn.netbuffer.springsecuritydemo.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StreamUtils;
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
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(data.getString("username"), data.getString("password"));
        return super.getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);
    }

}
