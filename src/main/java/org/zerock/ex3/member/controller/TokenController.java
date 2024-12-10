package org.zerock.ex3.member.controller;


import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.zerock.ex3.member.dto.MemberDTO;
import org.zerock.ex3.member.service.MemberService;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/token")
@Log4j2
@RequiredArgsConstructor
public class TokenController {
  
  private final MemberService memberService;
  
  @PostMapping("/make")
  public ResponseEntity<Map<String, String>> makeToken(@RequestBody MemberDTO memberDTO) {
    log.info("make token..............................");
    
    MemberDTO memberDTOResult = memberService.read(memberDTO.getMid(), memberDTO.getMpw());
    log.info(memberDTOResult);
    
    return null;
  }
}
