package cn.netbuffer.springsecuritydemo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import javax.annotation.Resource;

@Slf4j
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        log.debug("init InMemoryTokenRepositoryImpl");
        return new InMemoryTokenRepositoryImpl();
    }

    @Resource
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/your-login-path")
                .defaultSuccessUrl("/your-success-path")
                .permitAll()
                .and()
                .authorizeRequests()
                .antMatchers("/", "/info/**")
                .permitAll()
                .antMatchers("/admin/**")
                .hasAuthority("admin")
                .antMatchers("/test/**")
                .hasAuthority("test")
                .anyRequest()
                .authenticated()
                .and()
                .csrf()
                .disable()
                .exceptionHandling()
                .accessDeniedPage("/403.html");
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/info");
        http.rememberMe()
                .rememberMeParameter("rme")
                .userDetailsService(userDetailsService)
                .tokenRepository(persistentTokenRepository());

    }

}