package com.baeldung.security;

import com.baeldung.naming.PrivilegeNaming;
import com.baeldung.persistence.model.User;
import com.baeldung.service.DeviceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Collection;

@Component("myAuthenticationSuccessHandler")
public class MySimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Autowired
    ActiveUserStore activeUserStore;

    @Autowired
    private DeviceService deviceService;

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {
        handle(request, response, authentication);
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.setMaxInactiveInterval(30 * 60);

            String username = this.setUserNameBasedInAuthenticationInfo(authentication);
            LoggedUser user = new LoggedUser(username, activeUserStore);
            session.setAttribute("user", user);
        }
        clearAuthenticationAttributes(request);

        loginNotification(authentication, request);
    }

    private void loginNotification(Authentication authentication, HttpServletRequest request) {
        try {
            if (authentication.getPrincipal() instanceof User) {
                deviceService.verifyDevice(((User)authentication.getPrincipal()), request);
            }
        } catch (Exception e) {
            logger.error("An error occurred while verifying device or location", e);
            throw new RuntimeException(e);
        }

    }

    private String setUserNameBasedInAuthenticationInfo(Authentication authentication){
        return authentication.getPrincipal() instanceof User ? ((User)authentication.getPrincipal()).getEmail() :
                authentication.getName();
    }

    protected void handle(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {
        final String targetUrl = determineTargetUrl(authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(final Authentication authentication) {
        final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        boolean isUser = authorities.stream().anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(PrivilegeNaming.READ_PRIVILEGE))
                &&  authorities.stream().noneMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(PrivilegeNaming.MANAGER_PRIVILEGE));
        boolean isAdmin = authorities.stream().anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(PrivilegeNaming.WRITE_PRIVILEGE));
        boolean isManager = authorities.stream().anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(PrivilegeNaming.READ_PRIVILEGE))
                &&  authorities.stream().anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(PrivilegeNaming.MANAGER_PRIVILEGE));

        if (isUser) {
        	 String username = this.setUserNameBasedInAuthenticationInfo(authentication);

            return "/homepage.html?user=".concat(username);
        } else if (isAdmin) {
            return "/console.html";
        }else if(isManager){
            return "/management.html";
        }
        else {
            throw new IllegalStateException();
        }
    }

    protected void clearAuthenticationAttributes(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    public void setRedirectStrategy(final RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }
}