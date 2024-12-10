package org.zerock.ex3.member.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.zerock.ex3.member.entity.MemberEntity;

public interface MemberRepository extends JpaRepository<MemberEntity, String> {

}
