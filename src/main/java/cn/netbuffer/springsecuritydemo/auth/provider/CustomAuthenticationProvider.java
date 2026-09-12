package cn.netbuffer.springsecuritydemo.auth.provider;

import cn.netbuffer.springsecuritydemo.auth.token.CustomTokenAuthenticationToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

import java.util.List;

/**
 * 自定义 Token 认证提供者
 * <p>处理 {@link CustomTokenAuthenticationToken} 类型的认证请求，支持根据 Token 解析身份并赋予权限。</p>
 */
@Slf4j
public class CustomAuthenticationProvider implements AuthenticationProvider {

    public CustomAuthenticationProvider() {

    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomTokenAuthenticationToken customTokenAuthenticationToken = (CustomTokenAuthenticationToken) authentication;
        Object principalObj = customTokenAuthenticationToken.getPrincipal();
        Object credentialsObj = customTokenAuthenticationToken.getCredentials();

        if (principalObj == null || !StringUtils.hasText(principalObj.toString())) {
            throw new BadCredentialsException("Token is empty or invalid format");
        }

        String principal = principalObj.toString();
        String credentials = credentialsObj != null ? credentialsObj.toString() : "";
        log.debug("custom authenticate principal={}, credentials={}", principal, credentials);

        // 实际业务中可根据 principal 或 token 查询数据库/Redis/校验 JWT
        List<GrantedAuthority> grantedAuthorityList = AuthorityUtils.commaSeparatedStringToAuthorityList(principal);
        return new CustomTokenAuthenticationToken(credentials, grantedAuthorityList);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

}