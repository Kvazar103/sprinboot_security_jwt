package com.example.sprinboot_security_jwt.models;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Customer {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    @Column(unique = true)//індекс над цією колонкою і бд не буде записувати не унікальні значення
    private String login;
    private String password;
    private String role="ROLE_USER";// ролі в б мають починатися з ROLE_

}
