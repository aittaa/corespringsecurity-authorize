package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    //ConfigAttribute : 권한정보가 담긴다.
    //LinkedHashMap : 순서를 유지하는 해시맵 (자원의 순서가 중요하기에..)
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap) {
        this.requestMap = requestMap;
    }


    // 필수구현
    // 필터에서 당 매소드를 호출할 때 FilterInvocation이 들어온다. (FilterInvocation:요청정보)
    // But 이 인터페이스 구현하는매소드 방식은 다른 타입으로 들어가기에 이 인터페이스는 Object 파라미터를 전달받음.
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {


        HttpServletRequest request = ((FilterInvocation) object).getRequest();

        if(requestMap != null){
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
                RequestMatcher matcher = entry.getKey();

                if(matcher.matches(request)){ // url 매칭 확인
                    return entry.getValue(); // url 일치 시 권한정보 리턴
                }
            }
        }

        return null;
    }

//RequestMatcher : 요청된 자원의 url 매칭을 판별하기 위해 사용하는 클래스가 RequestMatcher 인터페이스를 구현한
// AntPathRequestMatcher이며 matches()를 사용하여 확인



    //이하는 당장은 구현 안해도 ok
    //DefaultFilterInvocationSecurityMetadataSource에서 가져옴
    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }






}


