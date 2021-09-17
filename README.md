# spring-security-demo
![](https://img.shields.io/static/v1?label=sppring-boot&message=2.5.4&color=blue)
![](https://img.shields.io/static/v1?label=sppring-security&message=2.5.4&color=green)
![](https://img.shields.io/static/v1?label=fastjson&message=1.2.78&color=blue)
> spring-security test project  
* https://github.com/netbuffer/spring-security-demo
* https://gitee.com/netbuffer/spring-security-demo
* https://docs.spring.io/spring-security/site/docs/current/reference/html5/

### help
* look for the default password generated from the console:`Using generated security password:` default generated user is `user` 
* [test login process](http://localhost:18000/app)  
![http request filter-chain](https://docs.spring.io/spring-security/site/docs/current/reference/html5/images/servlet/architecture/multi-securityfilterchain.png)  
```
@Secure
@RolesAllowed
@PreAuthorize
@PostAuthorize
@PreFilter
@PostFilter
```