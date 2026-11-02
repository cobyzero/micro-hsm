package com.security.hsm;

import com.security.hsm.config.HsmProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
@EnableConfigurationProperties(HsmProperties.class)
public class MicroHsmApplication {

    public static void main(String[] args) {
        SpringApplication.run(MicroHsmApplication.class, args);
    }
}

