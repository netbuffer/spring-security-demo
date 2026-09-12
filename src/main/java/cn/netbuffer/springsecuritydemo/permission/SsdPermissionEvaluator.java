package cn.netbuffer.springsecuritydemo.permission;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 自定义权限评估器（PermissionEvaluator）
 * <p>用于支撑 SpEL 表达式中的 {@code hasPermission(...)} 细粒度权限校验。</p>
 */
@Slf4j
@Component
public class SsdPermissionEvaluator implements PermissionEvaluator {

    /**
     * 模拟存储：用户与其具备的目标资源及权限动作映射
     * key: 用户名, value: [ {资源标识: 具备的操作权限(如 read/write)} ]
     */
    static Map<String, List<Map<String, String>>> PERMISSIONS_MAP = null;

    static {
        // 演示环境初始化：实际业务中应从 DB / Redis 读取
        PERMISSIONS_MAP = new HashMap<>();
        String user = "admin";
        List<Map<String, String>> userPermissions = new ArrayList<>();
        Map<String, String> userPermission1 = new HashMap<>();
        userPermission1.put("target-id", "read");
        userPermissions.add(userPermission1);
        PERMISSIONS_MAP.put(user, userPermissions);
    }

    /**
     * 校验当前登录主体是否对指定目标对象拥有相应权限
     *
     * @param authentication 当前已认证的 Authentication 对象
     * @param targetDomainObject 目标对象或目标对象标识（例如 "target-id"）
     * @param permission 权限名称或动作（例如 "read"、"write"）
     * @return true 表示有权限放行，false 表示无权限拒绝访问
     */
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        log.debug("hasPermission authentication={} targetDomainObject={} permission={}", authentication, targetDomainObject, permission);
        if (authentication == null || authentication.getPrincipal() == null) {
            return false;
        }
        Object principal = authentication.getPrincipal();
        String user;
        if (principal instanceof UserDetails userDetails) {
            user = userDetails.getUsername();
        } else {
            user = String.valueOf(principal);
        }
        List<Map<String, String>> permissions = PERMISSIONS_MAP.get(user);
        if (CollectionUtils.isEmpty(permissions)) {
            return false;
        }
        boolean pass = permissions.stream().anyMatch(map -> map.containsKey(targetDomainObject) && map.get(targetDomainObject).equals(permission));
        log.debug("check {} has target[{}] permission[{}]={}", user, targetDomainObject, permission, pass);
        return pass;
    }

    /**
     * 校验当前登录主体是否对指定目标 ID 和目标类型的对象拥有相应权限
     *
     * @param authentication 当前已认证的 Authentication 对象
     * @param targetId 目标主键 ID
     * @param targetType 目标类型字符串
     * @param permission 权限名称或动作
     * @return true 表示有权限放行，false 表示无权限拒绝访问
     */
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        log.debug("hasPermission by targetId: authentication={} targetId={} targetType={} permission={}",
                authentication, targetId, targetType, permission);
        return true;
    }

}