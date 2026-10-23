package com.example.shop.member;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

@Entity
public class Member {
    @Id Long id;
    String name;
    String email;
    String address;
    String myNumber;        // individual number (My Number)
    String birthDate;
}
