package com.cos.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

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

        // principalDetails를 세션에 담고(권한 관리를 위해서)
        // jwt토큰을 만들어서 응딥해주면 된다
        try {
            // username, password 받아서(request 안에 있음, json형식이라고 정하고 구현 )
            ObjectMapper om = new ObjectMapper();
            User user= om.readValue(request.getInputStream(), User.class);
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                    = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 정상인 로그인 시도, authenticationManager로 로그인 시도를 하면 principalDetilasService가 호출된다.
            // 그러면 loadUserByUsername이 실행된다
            // 알아서 authenticationManager가 인증을 해서 authentication을 리턴해준다(내 로그인한 정보를 리턴해준다)
            // 인증이 되었다는 것은 로그인이 되었다는 것이다.
            Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

            System.out.println("attempAuthetication 실행됨");
            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // attemp실행 후 인증이 정상적으로 되었으면 함수가 실행된다.
    //jwt토큰을 만들어서 request 요청한 사용자에게 jwt토큰을 response해줌
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // Hash암호 방식
        String jwtToken = JWT.create()
                .withSubject("corsToken")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10))) // 토큰의 만료시간(10분)
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("password", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cors"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
