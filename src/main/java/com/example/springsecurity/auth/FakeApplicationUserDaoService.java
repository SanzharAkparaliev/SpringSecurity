package com.example.springsecurity.auth;

import com.example.springsecurity.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;


import java.util.List;
import java.util.Optional;

import static com.example.springsecurity.security.ApplicationUserRole.ADMIN;
import static com.example.springsecurity.security.ApplicationUserRole.STUDENT;


@Repository("fake")
public class FakeApplicationUserDaoService  implements ApplicationUserDao{
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String userName) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> userName.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        STUDENT.getGrantedAuthorities(),
                        "annasmith",
                        passwordEncoder.encode("password")
                ),
            new ApplicationUser(
                    ADMIN.getGrantedAuthorities(),
                    "linda",
                    passwordEncoder.encode("password")
            )
        );
        return applicationUsers;
    }
}
