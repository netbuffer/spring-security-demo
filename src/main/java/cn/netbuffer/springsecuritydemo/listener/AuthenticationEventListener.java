package cn.netbuffer.springsecuritydemo.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * 认证事件监听器
 * <p>基于 Spring ApplicationEventPublisher 机制监听认证成功与失败事件，可用于统计、审计与风控等。</p>
 */
@Slf4j
@Component
public class AuthenticationEventListener {

    /**
     * 认证成功事件监听
     *
     * @param success 包含认证成功信息的事件对象
     */
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent success) {
        log.debug("login success auth={}", success.getAuthentication());
    }

    /**
     * 认证失败事件监听
     *
     * @param failures 包含认证失败原因及上下文的事件对象
     */
    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failures) {
        log.debug("login fail auth={}, exception={}", failures.getAuthentication(), failures.getException().getMessage());
    }
}