package cn.netbuffer.springsecuritydemo.component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;

/**
 * 自定义登出处理器
 * <p>用于在用户登出时记录日志、清理自定义缓存或关联资源等。</p>
 */
@Slf4j
public class CustomLogoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
        if (authentication == null) {
            log.debug("anonymous logout or no authentication found in current request");
            return;
        }
        Object principal = authentication.getPrincipal();
        String username;
        if (principal instanceof UserDetails userDetails) {
            username = userDetails.getUsername();
        } else {
            username = String.valueOf(principal);
        }
        log.debug("[{}] logout from system", username);
    }
}
