package com.ghost.leapigateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class LeapiGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(LeapiGatewayApplication.class, args);
    }

//    @Bean
//    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
//        return builder.routes()
//                .route("path_route", r -> r.path("/baidu")
//                        .uri("https://baidu.com"))
//                .route("host_route", r -> r.path("/lexiaoxin")
//                        .uri("https://blog.csdn.net/m0_74059961?spm=1011.2266.3001.5343"))
//                .build();
//    }
}
