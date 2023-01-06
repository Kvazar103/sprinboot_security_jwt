package com.example.sprinboot_security_jwt.controllers;

import com.example.sprinboot_security_jwt.dao.CustomerDAO;
import com.example.sprinboot_security_jwt.models.Customer;
import com.example.sprinboot_security_jwt.models.dto.CustomerDTO;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;

@RestController
@AllArgsConstructor
public class MainController {

    private CustomerDAO customerDAO;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;//базовий об'єкт який займається процесом аутентифікації

    @GetMapping("/")
    public String open(){
        return "open";
    }
    @PostMapping("/save")
    public void save(@RequestBody CustomerDTO customerDTO){
        Customer customer=new Customer();
        customer.setPassword(passwordEncoder.encode(customerDTO.getPassword()));//зразу енкодем пароль
        customer.setLogin(customerDTO.getName());
        customerDAO.save(customer);
    }
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody CustomerDTO customerDTO){  //метод логін для того що віддав нам токен
       Authentication authenticate= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(customerDTO.getName(),customerDTO.getPassword()));  //тут ми впроваджуємо об'єкт який має мати аутентифікацію(креденшили)
         // і коли ми його тут вставляєм то спрацьовує метод configure(AuthenticationManagerBuilder auth) з SecurityConfig і якщо він його там знайде то впроваде ідентифікацію(заповнить authenticate)
        if(authenticate!=null){ //якщо authenticate заповнений тоді згенеруємо токен
         String jwtToken= Jwts.builder().
                    setSubject(authenticate.getName()) //тут ми передаємо ім'я і саме його ми будемо кодувати
                 .setExpiration(new Date()) //час токена
                    .signWith(SignatureAlgorithm.HS512,"nazar".getBytes(StandardCharsets.UTF_8)) //тут є саме кодування
                    .compact(); //це позволить зробити стрінгу яка й буде являтися токеном
            System.out.println(jwtToken);
            HttpHeaders headers=new HttpHeaders();
            headers.add("Authorization","Bearer "+jwtToken);//додаємо в хедер наш токен
            return new ResponseEntity<>("you are log in",headers, HttpStatus.ACCEPTED);
        }
        return new ResponseEntity<>("zazazazaz",HttpStatus.FORBIDDEN);//якщо провірку не пройшло тоді заборонено
    }
    @GetMapping("/secure")
    public String secure(){
        return "secure data";
    }
}
