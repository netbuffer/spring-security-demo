package cn.netbuffer.springsecuritydemo.auth.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

/**
 * custom auth token info
 */
public class CustomTokenAuthenticationToken extends AbstractAuthenticationToken {

    private String token;

    public CustomTokenAuthenticationToken(String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        //parse token to get user
        return token.split(":")[1];
    }
}
