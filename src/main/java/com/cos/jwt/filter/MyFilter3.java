package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println(headerAuth);

            // 특정값이(cors - 추후에는 토큰)이 들어올때만 인증이 되게 처리
            // 토크을 만들어줘야. id, pw 가 정상적으로 들어와서 로그인이 완료되면 트콘을 만들어주 그걸 응답을 해준다
            // 요청할 때마다 header 에 Authorization에 value값으로 토큰을 가지고 오면
            // 그때 토큰이 넘이오면 이 토큰이 내가 만든 토큰이 맞는지 검증만 하면 됨(RSA, HS256)
            if(headerAuth.equals("cors")){
                chain.doFilter(req, res);
            }else{
                PrintWriter outPrinterWriter = res.getWriter();
                outPrinterWriter.println("인증 안됨");
            }
        }
    }
}
