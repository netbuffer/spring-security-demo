package cn.netbuffer.springsecuritydemo.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    @Resource
    private PasswordEncoder passwordEncoder;
    private String[] users = new String[]{"admin", "test"};

    /**
     * find user from storage(db/redis/es/ck...)
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //todo find user from database/redis...
        if (Arrays.binarySearch(users, username) < 0) {
            throw new UsernameNotFoundException(username + "not exist");
        }
        log.debug("loadUserByUsername invoked username={}", username);
        String password = passwordEncoder.encode(username);
        List<GrantedAuthority> grantedAuthorityList = AuthorityUtils.commaSeparatedStringToAuthorityList(username);
        log.debug("set grantedAuthorityList={} for username[{}]", grantedAuthorityList, username);
        return new User(username, password, grantedAuthorityList);
    }

}
