package io.security.corespringsecurity.service;


import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

//DB로부터 자원을 가져와서 매핑
public class SecurityResourceService {
    // 설정클래스에서 빈으로 받아올 것
    private final ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList(){

        /* 권한과 자원정보 가져와 매핑 */
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourceList = resourcesRepository.findAllResources();

        resourceList.forEach(resource -> {
           List<ConfigAttribute> configAttributeList = new ArrayList<>();

           resource.getRoleSet().forEach(role -> {
              configAttributeList.add(new SecurityConfig(role.getRoleName()));
           });
            result.put(new AntPathRequestMatcher(resource.getResourceName()), configAttributeList);

        });

        return result;
    }
    
}
