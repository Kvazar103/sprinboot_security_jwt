package com.example.sprinboot_security_jwt.dao;

import com.example.sprinboot_security_jwt.models.Customer;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerDAO extends JpaRepository<Customer,Integer> {
    Customer findCustomerByLogin(String login);
}
