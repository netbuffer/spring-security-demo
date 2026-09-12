package cn.netbuffer.springsecuritydemo;

import com.alibaba.fastjson2.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Spring Security 演示工程集成测试
 * <p>涵盖公开端点、表单登录、自定义登录、Token登录、方法级鉴权、权限评估器及 CSRF 校验等全流程测试。</p>
 */
@SpringBootTest
class SpringSecurityDemoApplicationTests {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    @Test
    @DisplayName("验证 Spring 上下文加载及公共放行接口")
    void contextLoads() throws Exception {
        mockMvc.perform(get("/info"))
                .andExpect(status().isOk())
                .andExpect(content().string("info"));

        mockMvc.perform(get("/info/appName"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("验证未登录用户访问受保护接口重定向至登录页")
    void testUnauthenticatedAccessRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/admin"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @DisplayName("验证自定义 PermissionEvaluator 细粒度权限校验")
    @WithMockUser(username = "admin", authorities = {"admin"})
    void testHasPermissionReadAndWrite() throws Exception {
        // admin 具备 target-id 的 read 权限
        mockMvc.perform(get("/app/resource/target-id/read"))
                .andExpect(status().isOk())
                .andExpect(content().string("ok"));

        // admin 不具备 target-id 的 write 权限，预期 403
        mockMvc.perform(get("/app/resource/target-id/write"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("验证自定义 JSON 登录、Session 鉴权、PostAuthorize 及登出全流程")
    void testCustomLoginAndSubsequentRequests() throws Exception {
        JSONObject loginData = new JSONObject();
        loginData.put("username", "admin");
        loginData.put("password", "admin");

        MvcResult loginResult = mockMvc.perform(post("/your-custom-login-path")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginData.toJSONString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("admin"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) loginResult.getRequest().getSession(false);
        assertNotNull(session, "Session should not be null after login");

        // 使用登录后的 session 访问受 admin 保护的端点
        mockMvc.perform(get("/admin").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string("admin"));

        // 测试带有 PostAuthorize 的端点：owner 与当前用户 admin 一致，允许访问
        mockMvc.perform(get("/app/resource").param("owner", "admin").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.owner").value("admin"));

        // 测试带有 PostAuthorize 的端点：owner 与当前用户 admin 不一致，预期 403
        mockMvc.perform(get("/app/resource").param("owner", "test").session(session))
                .andExpect(status().isForbidden());

        // 测试带有 PreAuthorize("hasAuthority('admin')") 端点
        mockMvc.perform(get("/app/access").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string("access"));

        // 测试自定义登出
        mockMvc.perform(post("/logout").with(csrf()).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/info"));
    }

    @Test
    @DisplayName("验证自定义 Header Token 登录与鉴权访问")
    void testCustomTokenLoginAndSubsequentRequests() throws Exception {
        MvcResult tokenLoginResult = mockMvc.perform(post("/your-custom-token-login-path")
                        .with(csrf())
                        .header("token", "bearer:admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user").value("admin"))
                .andReturn();

        MockHttpSession session = (MockHttpSession) tokenLoginResult.getRequest().getSession(false);
        assertNotNull(session, "Session should not be null after token login");

        // 使用 session 访问 admin 接口
        mockMvc.perform(get("/admin").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string("admin"));

        // 使用 session 访问 app 接口
        mockMvc.perform(get("/app").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string("app"));
    }

    @Test
    @DisplayName("验证标准 Form 登录流程")
    void testFormLogin() throws Exception {
        mockMvc.perform(post("/your-login-path")
                        .with(csrf())
                        .param("username", "test")
                        .param("password", "test"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/info"));
    }
}
