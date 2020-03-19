package com.baeldung.spring;

import java.util.*;

import com.baeldung.naming.PrivilegeNaming;
import com.baeldung.persistence.dao.PrivilegeRepository;
import com.baeldung.persistence.dao.RoleRepository;
import com.baeldung.persistence.dao.UserRepository;
import com.baeldung.persistence.model.Privilege;
import com.baeldung.persistence.model.Role;
import com.baeldung.persistence.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

    private boolean alreadySetup = false;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PrivilegeRepository privilegeRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // API

    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        if (alreadySetup) {
            return;
        }

        // == create initial privileges
        final Privilege readPrivilege = createPrivilegeIfNotFound(PrivilegeNaming.READ_PRIVILEGE);
        final Privilege writePrivilege = createPrivilegeIfNotFound(PrivilegeNaming.WRITE_PRIVILEGE);
        final Privilege passwordPrivilege = createPrivilegeIfNotFound(PrivilegeNaming.CHANGE_PASSWORD_PRIVILEGE);
        final Privilege managerPrivilege = createPrivilegeIfNotFound(PrivilegeNaming.MANAGER_PRIVILEGE);

        // == create initial roles
        final List<Privilege> adminPrivileges = new ArrayList<>(Arrays.asList(readPrivilege, writePrivilege, passwordPrivilege));
        final List<Privilege> userPrivileges = new ArrayList<>(Arrays.asList(readPrivilege, passwordPrivilege));
        final List<Privilege> managerPriviliges = new ArrayList<>(Arrays.asList(readPrivilege, managerPrivilege, passwordPrivilege));
        final Role adminRole = createRoleIfNotFound("ROLE_ADMIN", adminPrivileges);
        final Role managerRole = createRoleIfNotFound("ROLE_MANAGER", managerPriviliges);
        createRoleIfNotFound("ROLE_USER", userPrivileges);

        // == create initial user
        createUserIfNotFound("test@test.com", "Test", "Test", "test", new ArrayList<>(Collections.singletonList(adminRole)));
        // == create initial manager user
        createUserIfNotFound("manager@manager.com", "Manager", "Manager", "manager", new ArrayList<>(Collections.singletonList(managerRole)));

        alreadySetup = true;
    }

    @Transactional
    private final Privilege createPrivilegeIfNotFound(final String name) {
        Privilege privilege = privilegeRepository.findByName(name);
        if (privilege == null) {
            privilege = new Privilege(name);
            privilege = privilegeRepository.save(privilege);
        }
        return privilege;
    }

    @Transactional
    private final Role createRoleIfNotFound(final String name, final Collection<Privilege> privileges) {
        Role role = roleRepository.findByName(name);
        if (role == null) {
            role = new Role(name);
        }
        role.setPrivileges(privileges);
        role = roleRepository.save(role);
        return role;
    }

    @Transactional
    private final User createUserIfNotFound(final String email, final String firstName, final String lastName, final String password, final Collection<Role> roles) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            user = new User();
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setPassword(passwordEncoder.encode(password));
            user.setEmail(email);
            user.setEnabled(true);
        }
        user.setRoles(roles);
        user = userRepository.save(user);
        return user;
    }

}