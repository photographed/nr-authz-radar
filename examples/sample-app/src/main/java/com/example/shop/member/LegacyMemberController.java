package com.example.shop.member;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** Old mobile app API (v0). The current app uses /api/v1/me. */
@RestController
public class LegacyMemberController {
    interface MemberRepository extends JpaRepository<Member, Long> { }

    private final MemberRepository members;

    LegacyMemberController(MemberRepository members) {
        this.members = members;
    }

    @GetMapping("/api/v0/members/{id}/profile")
    public Member profile(@PathVariable Long id) {
        return members.findById(id).orElseThrow();
    }
}
