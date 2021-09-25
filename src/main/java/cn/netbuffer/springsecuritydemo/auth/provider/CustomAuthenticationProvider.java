package cn.netbuffer.springsecuritydemo.auth.provider;

import cn.netbuffer.springsecuritydemo.auth.token.CustomTokenAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import java.util.List;

@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

    public CustomAuthenticationProvider() {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomTokenAuthenticationToken customTokenAuthenticationToken = (CustomTokenAuthenticationToken) authentication;
        String principal = customTokenAuthenticationToken.getPrincipal().toString();
        String credentials = customTokenAuthenticationToken.getCredentials().toString();
        log.debug("custom authenticate principal={},credentials={}", principal, credentials);
        //find from db
        List<GrantedAuthority> grantedAuthorityList = AuthorityUtils.commaSeparatedStringToAuthorityList(principal);
        return new CustomTokenAuthenticationToken(credentials, grantedAuthorityList);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

}