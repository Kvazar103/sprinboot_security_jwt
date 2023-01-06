package com.example.sprinboot_security_jwt.security.filters;

import com.example.sprinboot_security_jwt.dao.CustomerDAO;
import com.example.sprinboot_security_jwt.models.Customer;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

public class CustomFilter extends OncePerRequestFilter { //OncePerRequestFilter в нього вбудований механізм який відпрацює лише один раз за ріквест

    private CustomerDAO customerDAO;

    public CustomFilter(CustomerDAO customerDAO) {
        this.customerDAO = customerDAO;
    }

    @Override
    protected void doFilterInternal( //необхідний метод для OncePerRequestFilter
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        //тут ми відхоплюємо запити які прийдуть зі сторони користувача з токеном

            String authorization =request.getHeader("Authorization");//тут ми кажемо який хедер хочемо відхопити
            if(authorization!=null && authorization.startsWith("Bearer ")){//якщо authorization не пустий і починається з префіксу Bearer тоді це насправді токен
                String token =authorization.replace("Bearer ","");//ми зможемо "відкусити" токен
                String subject= Jwts.parser() //розшифровуєм токен
                        .setSigningKey("nazar".getBytes(StandardCharsets.UTF_8)) //без наявності секретного ключа нічого не вийде
                        .parseClaimsJws(token)//після розшифровки ми витягуємо інформацію з нього
                        .getBody() //вся інформація знаходиться тут
                        .getSubject(); //з body ми витягуємо лише саму необхідну інформацію
                System.out.println(subject);//asd
                Customer customerByLogin=customerDAO.findCustomerByLogin(subject);
                System.out.println(customerByLogin);
                if(customerByLogin!=null){ //якщо ми найшли customer(бо якщо нічого не знайде в бд то воно поверне null)
                    SecurityContextHolder.getContext().setAuthentication(//аутентифікація
                            new UsernamePasswordAuthenticationToken(
                                    customerByLogin.getLogin(),
                                    customerByLogin.getPassword(),
                                    Collections.singletonList(new SimpleGrantedAuthority(customerByLogin.getRole()))
                            )
                    );
                }
            }
            filterChain.doFilter(request,response);//без того не буде працювати
    }

}
