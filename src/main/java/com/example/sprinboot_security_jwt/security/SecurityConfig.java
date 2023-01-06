package com.example.sprinboot_security_jwt.security;

import com.example.sprinboot_security_jwt.dao.CustomerDAO;
import com.example.sprinboot_security_jwt.models.Customer;
import com.example.sprinboot_security_jwt.security.filters.CustomFilter;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

@Configuration //анотація щоб створювати @BEAN
@EnableWebSecurity //впроваджує дефолтні налаштування щоб наше секюріті почала обробку запитів
@AllArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private CustomerDAO customerDAO;

    @Bean // те що повертається з метода робиться об'єктом і кладе його під контейнер(який можна використовувати в MainController
    PasswordEncoder passwordEncoder(){ //розшифровує пароль
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // тут ми приймаємо логін пароль і знайти обєкт в базі даних
        auth.userDetailsService(username -> {//знайти обєкт в бд
            System.out.println("login trig"); //вибиває коли ми логінемося
           Customer customer= customerDAO.findCustomerByLogin(username);
           return new User(customer.getLogin(),
                   customer.getPassword(),
                   Arrays.asList(new SimpleGrantedAuthority(customer.getRole())));
        });

    }
    @Bean
    public CustomFilter customFilter(){
        return new CustomFilter(customerDAO);
    }
    //для конфігурації для інших наприклад(react localhost:3000)
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        //тут ми пишемо з яких додаткових хостів можна звертатися до нашої програми(які методи дозволені,хедери і.т.д)
        CorsConfiguration configuration=new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000","http://localhots:4200"));//з тих хостів ми дозволяємо звертатися до нашої програми
        configuration.addAllowedHeader("*");//header- додаткова метаінформація(логін пароль і.т.д)метод каже що всі хедери позволені
        configuration.setAllowedMethods(Arrays.asList( //тут ми пишемо які методи дозволені в хості (також можна забороняти будь-які методи з хоста)
                HttpMethod.GET.name(), //.name() - для того щоб перетворити назву http метода на стрінгу
                HttpMethod.PUT.name(),
                HttpMethod.POST.name(),
                HttpMethod.PATCH.name(),
                HttpMethod.DELETE.name(),
                HttpMethod.HEAD.name()
        ));
        configuration.addExposedHeader("Authorization");//щоб бачила наші хедери які являються нашими кастомними
        UrlBasedCorsConfigurationSource source=  new UrlBasedCorsConfigurationSource(); //привязуємо конфігурації до певної урли
        source.registerCorsConfiguration("/**",configuration);//будь-які урли які будуть тут появлятися ми цю конфігурацію застосовуємо
        return source;
        //після того як бін готовий викликаємо його в configure в .and().cors().configurationSource(corsConfigurationSource())
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {//позволяє поставити цей обєкт в bean контейнер
        // і після цього з bean контейнера його можна викликати в maincontroller
        return super.authenticationManager();//тут ми беремо менеджер аутентифікації який присутній в WebSecurityConfigurerAdapter і робимо з нього bean
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // тут ми конфігуруємо http request (їхні дозволи і заборони)
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET,"/","/open").permitAll()
                .antMatchers(HttpMethod.POST,"/save").permitAll()
                .antMatchers(HttpMethod.POST,"/login").permitAll()
                .antMatchers(HttpMethod.GET,"/secure").hasAnyRole("ADMIN","USER") //доступ до урли лише ті хто має певну роль(ADMIN і USER)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//щоб не зберігалася сесія
        // бо якщо буде зберігатися сесія сервак буде кешувати токен(він може мати закешований і все одно пустить якщо буде заборонено)
                .and().cors().configurationSource(corsConfigurationSource()) //за замовчуванням дозволено зробити запит до ендпоїнтів тільки з одного сервака(запит з localhost:8080 тільки на localhost:8080)
                .and().addFilterBefore(
//                        (servletRequest, servletResponse, filterChain) ->{//зробимо кастомний фільтер(фільтер - це функціональний інтерфейся) для того щоб формувати токен
//                    //всі запити проходять через фільтер
//                   System.out.println("custom filter");
//                    //servletRequest-це ріквест від клієнта servletResponse-це те що повинні відати клієнту
//
//                     HttpServletRequest request=(HttpServletRequest) servletRequest;//приводом його до типу HttpServletRequest
//                     String authorization =request.getHeader("Authorization");//тут ми кажемо який хедер хочемо відхопити
//                            if(authorization!=null && authorization.startsWith("Bearer ")){//якщо authorization не пустий і починається з префіксу Bearer тоді це насправді токен
//                                String token =authorization.replace("Bearer ","");//ми зможемо "відкусити" токен
//                              String subject=Jwts.parser() //розшифровуєм токен
//                                        .setSigningKey("nazar".getBytes(StandardCharsets.UTF_8)) //без наявності секретного ключа нічого не вийде
//                                        .parseClaimsJws(token)//після розшифровки ми витягуємо інформацію з нього
//                                        .getBody() //вся інформація знаходиться тут
//                                        .getSubject(); //з body ми витягуємо лише саму необхідну інформацію
//                                System.out.println(subject);//asd
//                                Customer customerByLogin=customerDAO.findCustomerByLogin(subject);
//                                System.out.println(customerByLogin);
//                                if(customerByLogin!=null){ //якщо ми найшли customer(бо якщо нічого не знайде в бд то воно поверне null)
//                                    SecurityContextHolder.getContext().setAuthentication(//аутентифікація
//                                            new UsernamePasswordAuthenticationToken(
//                                                    customerByLogin.getLogin(),
//                                                    customerByLogin.getPassword(),
//                                                    Collections.singletonList(new SimpleGrantedAuthority(customerByLogin.getRole()))
//                                            )
//
//                                    );
//                                }
//                            }
//                     filterChain.doFilter(servletRequest,servletResponse);//без того не буде працювати
//                } ,
               //зверху спосіб без customFilter()
                customFilter(),  //робим фільтер кращим способом
                        UsernamePasswordAuthenticationFilter.class); //ми додаємо фільтер до того як спрацює UsernamePasswordAuthenticationFilter.class
    }
}
