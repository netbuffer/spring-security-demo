package cn.netbuffer.springsecuritydemo.auth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

/**
 * 自定义 Token 认证对象
 * <p>封装从 HTTP Header ("token") 中提取的 Token 信息及解析出的用户名与权限列表。</p>
 */
public class CustomTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;
    private final String principal;

    public CustomTokenAuthenticationToken(String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        if (token != null && token.contains(":")) {
            this.principal = token.split(":", 2)[1];
        } else {
            this.principal = token;
        }
        if (authorities != null && !authorities.isEmpty()) {
            super.setAuthenticated(true);
        }
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
