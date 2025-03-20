package com.coffeebean.domain.user.user.controller;

import com.coffeebean.domain.user.MyPageResponse;
import com.coffeebean.domain.user.user.Address;
import com.coffeebean.domain.user.user.dto.EmailVerificationRequest;
import com.coffeebean.domain.user.user.dto.SignupReqBody;
import com.coffeebean.domain.user.user.enitity.User;
import com.coffeebean.domain.user.user.repository.UserRepository;
import com.coffeebean.domain.user.user.service.EmailVerificationService;
import com.coffeebean.domain.user.user.service.UserService;
import com.coffeebean.global.annotation.Login;
import com.coffeebean.global.dto.RsData;
import com.coffeebean.global.exception.ServiceException;
import com.coffeebean.global.util.CustomUserDetails;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.buf.UEncoder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final EmailVerificationService emailVerificationService;

    // 이메일 인증: 사용자가 이메일로 받은 인증 코드를 제출하여 이메일 인증을 완료
    @PostMapping("/request-verification")
    public RsData<Void> requestEmailVerification(@RequestParam("email") String email) {
        try {
            emailVerificationService.sendVerificationEmail(email);
            return new RsData<>("200-1", "인증번호가 이메일로 전송되었습니다.");
        } catch (Exception e) {
            throw new ServiceException("500-1", "이메일 발송 실패: " + e.getMessage());
        }
    }

    // 이메일 인증 확인
    @PostMapping("/verify-email")
    public RsData<Void> verifyEmail(@RequestBody @Valid EmailVerificationRequest emailVerificationRequest) {
        boolean result = emailVerificationService.verifyEmail(emailVerificationRequest.getEmail(), emailVerificationRequest.getCode());
        if (!result) {
            throw new ServiceException("400-2", "이메일 인증 실패");
        }
        return new RsData<>("200-2", "이메일 인증 성공");
    }

    // 회원가입
    @PostMapping("/signup")
    public RsData<User> signup(@RequestBody @Valid SignupReqBody signupRequest, BindingResult bindingResult) {
        // 유효성 검사
        if (bindingResult.hasErrors()) {
            StringBuilder errorMessage = new StringBuilder();
            bindingResult.getAllErrors().forEach(error -> errorMessage.append(error.getDefaultMessage()).append("\n"));
            throw new ServiceException("400-4", errorMessage.toString().trim());
        }

        // 이메일 중복 확인
        userService.findByEmail(signupRequest.getEmail())
                .ifPresent(user -> {
                    throw new ServiceException("409-1", "이미 사용중인 이메일입니다.");
                });

        // 회원가입 진행
        User user = userService.create(signupRequest);
        return new RsData<>("200-3", "회원가입이 완료되었습니다.", user);
    }

    // 회원 이름 변경
    @PostMapping("/modify/name")
    // @Login CustomUserDetails userDetails
    public RsData<String> modifyName(@RequestParam("email") String email, @RequestParam("newName") String  newName) {
        // 이름 수정 요청
        User user = userService.modifyName(email, newName);

        return new RsData<>("200-4", "이름이 성공적으로 변경되었습니다.",user.getName());
    }

    // 비밀번호 변경
    @PostMapping("/modify/password")
    public RsData<String> modifyPassword(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        String oldPassword = requestBody.get("oldPassword");
        String newPassword = requestBody.get("newPassword");
        userService.modifyPassword(email, oldPassword, newPassword);
        return new RsData<>("200-1", "비밀번호 변경 완료");
    }


    // 주소 변경
    @PostMapping("/modify/address")
    public RsData<Address> modifyAddress(@RequestBody Map<String, String> requestBody) {
        String email = requestBody.get("email");
        String city = requestBody.get("city");
        String street = requestBody.get("street");
        String zipcode = requestBody.get("zipcode");

        // 주소 수정 요청
        User user = userService.modifyAddress(email,city,street,zipcode);

        return new RsData<>("200-5", "주소가 성공적으로 변경되었습니다.", user.getAddress());
    }


    // 관리자 로그인
    @PostMapping("/admin/login")
    public RsData<String> adminLogin(@RequestBody Map<String, String> credentials, HttpServletResponse response) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        String token = userService.loginAdmin(username, password, response);

        return new RsData<>("200-1", "관리자 로그인 성공", token);
    }

    // 일반 회원 로그인
    @PostMapping("/login")
    public RsData<String> userLogin(@RequestBody Map<String, String> credentials, HttpServletResponse response) {
        String email = credentials.get("email");
        String password = credentials.get("password");

        Map<String, String> loginResult = userService.loginUser(email, password, response); // 사용자 이름과 토큰 반환
        String message = String.format("%s님 반갑습니다.", loginResult.get("userName"));
        String token = loginResult.get("token");

        return new RsData<>("200-2", message, token);
    }

    @PostMapping("/logout")
    public ResponseEntity<RsData<String>> logout(HttpServletResponse response) {
        // 쿠키 삭제 (token 이름으로 설정된 JWT 삭제)
        ResponseCookie cookie = ResponseCookie.from("token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(0) // 쿠키 즉시 삭제
                .sameSite("Strict")
                .build();

        response.addHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(new RsData<>("200-4", "로그아웃 성공", null));
    }


}
