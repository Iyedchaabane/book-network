package com.ichaabane.book_network.auth;

import com.ichaabane.book_network.email.EmailService;
import com.ichaabane.book_network.email.EmailTemplateName;
import com.ichaabane.book_network.exception.CodeNotVerifiedException;
import com.ichaabane.book_network.exception.ExpiredTokenException;
import com.ichaabane.book_network.exception.InvalidTokenException;
import com.ichaabane.book_network.exception.PasswordMismatchException;
import com.ichaabane.book_network.role.RoleRepository;
import com.ichaabane.book_network.security.JwtService;
import com.ichaabane.book_network.user.*;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;

import static com.ichaabane.book_network.user.TokenType.ACCOUNT_ACTIVATION;
import static com.ichaabane.book_network.user.TokenType.FORGOT_PASSWORD;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailService emailService;
    private final TokenRepository tokenRepository;

    @Value("${application.mailing.frontend.activation-url}")
    private String activationUrl;

    @Value("${application.mailing.frontend.reset-url}")
    private String resetUrl;

    public void register(RegistrationRequest registrationRequest) throws MessagingException {
        var userRole = roleRepository.findByName("USER")
                .orElseThrow( () -> {
                    log.error("USER role not found in the database");
                    return new IllegalStateException("User Role Not Found");
                });
        User user = User
                .builder()
                .firstName(registrationRequest.getFirstname())
                .lastName(registrationRequest.getLastname())
                .email(registrationRequest.getEmail())
                .password(passwordEncoder.encode(registrationRequest.getPassword()))
                .accountLocked(false)
                .enabled(false)
                .roles(List.of(userRole))
                .build();

        userRepository.save(user);
        log.info("Registration successful for user: {}", user.getEmail());
        sendValidationEmail(user);
    }

    private void sendValidationEmail(User user) throws MessagingException {
        var newToken = generateAndSaveActivationToken(user , ACCOUNT_ACTIVATION);

        emailService.sendEmail(
                user.getEmail(),
                user.getFullName(),
                EmailTemplateName.ACTIVATE_ACCOUNT,
                activationUrl,
                newToken,
                "Account activation"
        );
        log.info("Activation email sent to {}", user.getEmail());
    }

    private String generateAndSaveActivationToken(User user , TokenType type) {
        // Generate a token
        String generatedToken = generateActivationCode(6);

        Token token = Token.builder()
                .token(generatedToken)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(15))
                .type(type)
                .user(user)
                .build();

        tokenRepository.save(token);
        return generatedToken;
    }

    private String generateActivationCode(int length) {
        String code = "0123456789";
        StringBuilder activationCode = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for(int i = 0; i < length; i++) {
            int numberIndex = random.nextInt(code.length());
            activationCode.append(code.charAt(numberIndex));
        }
        return activationCode.toString();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

        var authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        var claims = new HashMap<String, Object>();
        var user = ((User) authentication.getPrincipal());
        claims.put("fullName", user.getFullName());

        var jwtToken = jwtService.generateToken(claims, (User) authentication.getPrincipal());

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    @Transactional
    public void activateAccount(String code) throws MessagingException {
        var validToken = tokenRepository.findByTokenAndType(code, ACCOUNT_ACTIVATION)
                .orElseThrow(() -> {
                    log.warn("Invalid activation token: {}", code);
                    return new InvalidTokenException("Invalid activation token");
                });

        if (LocalDateTime.now().isAfter(validToken.getExpiresAt())) {
            log.warn("Expired activation token for {}. Sending new token", validToken.getUser().getEmail());
            sendValidationEmail(validToken.getUser());
            throw new ExpiredTokenException("Token expired . A new token has been send to the same email");
        }

        var user = userRepository.findById(validToken.getUser().getId())
                .orElseThrow(() -> {
                    log.warn("No user found with Id: {}", validToken.getUser().getId());
                    return new UsernameNotFoundException("User not found");
                });

        user.setEnabled(true);
        userRepository.save(user);
        validToken.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(validToken);

        log.info("Account successfully activated for user: {}", user.getEmail());
    }

    @Transactional
    public void forgotPassword(String email) throws MessagingException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("No user found with email: {}", email);
                    return new UsernameNotFoundException("User not found");
                });

        String token = generateAndSaveActivationToken(user, FORGOT_PASSWORD);

        emailService.sendEmail(
                user.getEmail(),
                user.getFullName(),
                EmailTemplateName.FORGOT_PASSWORD,
                resetUrl,
                token,
                "Password reset request"
        );

        log.info("Password reset email sent to {}", user.getEmail());
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            log.warn("Password mismatch for token: {}", request.getToken());
            throw new PasswordMismatchException("Passwords do not match");
        }

        Token validToken = tokenRepository.findByTokenAndType(request.getToken(), FORGOT_PASSWORD)
                .orElseThrow(() -> {
                    log.warn("Invalid password reset token: {}", request.getToken());
                    return new InvalidTokenException("Invalid reset token");
                });

        if (LocalDateTime.now().isAfter(validToken.getExpiresAt())) {
            log.warn("Expired password reset token for user: {}", validToken.getUser().getEmail());
            throw new ExpiredTokenException("Token expired");
        }

        if (validToken.getValidatedAt() == null) {
            log.warn("Unverified reset code for user: {}", validToken.getUser().getEmail());
            throw new CodeNotVerifiedException("Code not verified");
        }

        User user = validToken.getUser();
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        log.info("Password successfully updated for user: {}", user.getEmail());
    }

    @Transactional
    public void verifyResetToken(String otp) {
        Token resetToken = tokenRepository.findByTokenAndType(otp, FORGOT_PASSWORD)
                .orElseThrow(() -> {
                    log.warn("Invalid verification token: {}", otp);
                    return new InvalidTokenException("Invalid reset token");
                });

        if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("Expired verification token: {}", otp);
            throw new ExpiredTokenException("Token expired");
        }

        resetToken.setValidatedAt(LocalDateTime.now());
        tokenRepository.save(resetToken);

        log.info("Reset code successfully verified for user: {}", resetToken.getUser().getEmail());
    }
}
