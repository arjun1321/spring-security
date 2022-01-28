package com.arjunkumar.springsecurity.service;

import com.arjunkumar.springsecurity.domain.MyUserDetails;
import com.arjunkumar.springsecurity.model.User;
import com.arjunkumar.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//        return new MyUserDetails(username);

        Optional<User> user = userRepository.findByUsername(username);
        user.orElseThrow(() -> new UsernameNotFoundException("Not Found: " + username));

        return user.map(MyUserDetails::new).get();
    }
}
