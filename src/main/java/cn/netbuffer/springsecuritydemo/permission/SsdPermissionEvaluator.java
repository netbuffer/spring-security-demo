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

@Slf4j
@Component
public class SsdPermissionEvaluator implements PermissionEvaluator {

    static Map<String, List<Map<String, String>>> PERMISSIONS_MAP = null;

    static {
        //todo get from db/redis/...
        PERMISSIONS_MAP = new HashMap<>();
        String user = "admin";
        List<Map<String, String>> userPermissions = new ArrayList<>();
        Map<String, String> userPermission1 = new HashMap<>();
        userPermission1.put("target-id", "read");
        userPermissions.add(userPermission1);
        PERMISSIONS_MAP.put(user, userPermissions);
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        // 在这里实现自定义的权限验证逻辑
        // 返回true表示有权限，返回false表示无权限
        log.debug("hasPermission authentication={} targetDomainObject={} permission={}", authentication, targetDomainObject, permission);
        String user = ((UserDetails) authentication.getPrincipal()).getUsername();
        List<Map<String, String>> permissions = PERMISSIONS_MAP.get(user);
        if (CollectionUtils.isEmpty(permissions)) {
            return false;
        }
        boolean pass = permissions.stream().anyMatch(map -> map.containsKey(targetDomainObject) && map.get(targetDomainObject).equals(permission));
        log.debug("check {} has target[{}] permission[{}]={}", user, targetDomainObject, permission, pass);
        return pass;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        // 在这里实现自定义的权限验证逻辑
        // 返回true表示有权限，返回false表示无权限
        return true;
    }

}