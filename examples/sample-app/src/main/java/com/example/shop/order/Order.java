package com.example.shop.order;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;

@Entity
public class Order {
    @Id @GeneratedValue Long id;
    String ownerId;
    String shippingAddress;
    String phone;
    String status;
}
