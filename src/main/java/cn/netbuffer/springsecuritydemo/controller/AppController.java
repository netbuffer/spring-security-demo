package cn.netbuffer.springsecuritydemo.controller;

import cn.netbuffer.springsecuritydemo.pojo.DataObject;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/app")
public class AppController {

    @GetMapping
    public String get() {
        return "app";
    }

    @PreAuthorize("hasAuthority('admin')")
    @GetMapping("access")
    public String access() {
        return "access";
    }

    @PostAuthorize("returnObject.owner == principal.username")
    @GetMapping("resource")
    public DataObject resource(String owner) {
        log.debug("resource get principal={}", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        DataObject dataObject = new DataObject();
        dataObject.setOwner(owner);
        return dataObject;
    }

    @GetMapping("resource/target-id/read")
    @PreAuthorize("hasPermission('target-id','read')")
    public String resourceHasPermissionRead() {
        return "ok";
    }

    @GetMapping("resource/target-id/write")
    @PreAuthorize("hasPermission('target-id','write')")
    public String resourceHasPermissionWrite() {
        return "ok";
    }

    @PostMapping("csrf-test")
    public Object csrfTest(@RequestBody Map data) {
        log.debug("RequestContextHolder.currentRequestAttributes()={}", RequestContextHolder.currentRequestAttributes());
        return data;
    }

}
