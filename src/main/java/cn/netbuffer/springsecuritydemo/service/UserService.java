package cn.netbuffer.springsecuritydemo.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class UserService implements UserDetailsService {

    @Resource
    private PasswordEncoder passwordEncoder;

    //login process
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //todo find user from database/redis...
        if (!username.equals("admin")) {
            throw new UsernameNotFoundException(username+"not exist");
        }
        log.debug("loadUserByUsername invoked username={}", username);
        String password = passwordEncoder.encode("admin");
        List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        return new User(username, password, grantedAuthorityList);
    }

}
