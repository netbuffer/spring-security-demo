package cn.netbuffer.springsecuritydemo.service;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.List;

/**
 * 自定义 UserDetailsService 实现类
 * <p>根据用户名加载用户详情（包括密码、权限列表等）。示例中内置了 "admin" 和 "test" 两个用户。</p>
 */
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    @Resource
    private PasswordEncoder passwordEncoder;

    /**
     * 示例允许登录的用户名列表（注意需保持排序以供 binarySearch 使用）
     */
    private final String[] users = new String[]{"admin", "test"};

    /**
     * 根据用户名加载用户信息
     * <p>实际项目中通常从数据库、Redis 等存储中查询。</p>
     *
     * @param username 用户输入的用户名
     * @return 包含用户名、加密后密码与权限信息的 UserDetails 对象
     * @throws UsernameNotFoundException 当用户不存在时抛出
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null || Arrays.binarySearch(users, username) < 0) {
            throw new UsernameNotFoundException("User [" + username + "] does not exist");
        }
        log.debug("loadUserByUsername invoked username={}", username);
        // 演示环境：密码即为用户名自身经过 DelegatingPasswordEncoder 编码后的密文
        String password = passwordEncoder.encode(username);
        List<GrantedAuthority> grantedAuthorityList = AuthorityUtils.commaSeparatedStringToAuthorityList(username);
        log.debug("set grantedAuthorityList={} for username[{}]", grantedAuthorityList, username);
        return new User(username, password, grantedAuthorityList);
    }

}
