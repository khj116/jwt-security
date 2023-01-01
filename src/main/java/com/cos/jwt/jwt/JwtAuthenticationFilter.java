package com.cos.jwt.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// 스프링 시큐리티 에서 usernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username,password를 전송하면(post)
// UsernamePasswordAuthenticationFilter가 작동함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // authenticationManager로 로그인 시도하는 메소드
    // /login요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("로그인 시도햇니???");

        // username, password 받아서
        // 정상인 로그인 시도, authenticationManager로 로그인 시도를 하면 principalDetilasService가 호출된다.
        // 그러면 loadUserByUsername이 실행된다
        // principalDetails를 세션에 담고(권한 관리를 위해서)
        // jwt토큰을 만들어서 응딥해주면 된다

        return super.attemptAuthentication(request, response);
    }
}
