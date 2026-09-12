package cn.netbuffer.springsecuritydemo.pojo;

import lombok.Data;

/**
 * 示例资源数据传输实体
 * <p>用于测试 {@code @PostAuthorize("returnObject.owner == principal.username")} 方法返回值后置鉴权。</p>
 */
@Data
public class DataObject {

    /**
     * 资源所属用户
     */
    private String owner;

    /**
     * 资源内容
     */
    private String data;

}
