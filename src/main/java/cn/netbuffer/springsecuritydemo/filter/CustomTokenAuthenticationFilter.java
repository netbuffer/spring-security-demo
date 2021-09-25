package cn.netbuffer.springsecuritydemo.filter;

import cn.netbuffer.springsecuritydemo.auth.token.CustomTokenAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class CustomTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public CustomTokenAuthenticationFilter() {
        super(new AntPathRequestMatcher("/your-custom-token-login-path", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("====================================custom token auth process============================");
        String token = request.getHeader("token");
        CustomTokenAuthenticationToken customTokenAuthenticationToken = new CustomTokenAuthenticationToken(token, null);
        return super.getAuthenticationManager().authenticate(customTokenAuthenticationToken);
    }

}