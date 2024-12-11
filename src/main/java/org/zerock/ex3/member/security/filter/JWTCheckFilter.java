package org.zerock.ex3.member.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.ex3.member.security.auth.CustomUserPrincipal;
import org.zerock.ex3.member.security.util.JWTUtil;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

//187p
@Component
@RequiredArgsConstructor
@Log4j2
public class JWTCheckFilter extends OncePerRequestFilter {
  
  private final JWTUtil jwtUtil;
  
  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
    
    //193p
    if (request.getServletPath().startsWith("/api/v1/token/")) {
      return true;
    }
    
    //경로지정 필요
    return false;
  }
  
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws SecurityException, IOException {
    log.info("JWTCheckFilter doFilter...................");
    
    log.info("requestURL: " + request.getRequestURI());
    
    String headerStr = request.getHeader("Authorization");
    
    log.info("headerStr: " + headerStr);
    
    //AccessToken이 없는 경우
    if (headerStr==null || !headerStr.startsWith("Bearer ")){
      handleException(response, new Exception("ACCESS TOKEN NOT FOUNT"));
      return;
    }
    
    
//    194p
    String accessToken = headerStr.substring(7);
    
    try {
      
      Map<String, Object> tokenMap = jwtUtil.validateToken(accessToken);
      
      //토큰 검증에 문제가 없다.
      log.info("tokenMap: " + tokenMap);
      
      String mid = tokenMap.get("mid").toString();
      
      //권한이 여러개인 경우에는 ,로 구분해서 처리
      String[] roles = tokenMap.get("role").toString().split(",");
      
      //토큰 검증 결과를 이용해서 aAuthentication 객체를 생성
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
          new CustomUserPrincipal(mid),
          null,
          Arrays.stream(roles).map(role -> new SimpleGrantedAuthority("ROLE_" + role))
              .collect(Collectors.toList())
      );
      
      //SecutityContextHolder에 Authentication 객체를 저장
      //이후에 SecurityContextHolder를 이용해서 Authentication객체를 꺼내서 사용할 수 있다.
      SecurityContext context = SecurityContextHolder.getContext();
      context.setAuthentication(authenticationToken);
      
      filterChain.doFilter(request, response);
      
    } catch (Exception e) {
      handleException(response, e);
    }
  }
  
  private void handleException(HttpServletResponse response, Exception e)throws IOException {
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.setContentType("application/json");
    response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
    
  }
}















