package com.coffeebean.domain.order.order.controller;

import com.coffeebean.domain.order.order.DeliveryStatus;
import com.coffeebean.domain.order.order.OrderDetailDto;
import com.coffeebean.domain.order.order.OrderDto;
import com.coffeebean.domain.order.order.OrderStatus;
import com.coffeebean.domain.order.order.dto.OrderListDto;
import com.coffeebean.domain.order.order.dto.OrderListResponseDto;
import com.coffeebean.domain.order.order.service.OrderService;
import com.coffeebean.domain.user.user.dto.EmailVerificationRequest;
import com.coffeebean.domain.user.user.service.EmailVerificationService;
import com.coffeebean.global.annotation.Login;
import com.coffeebean.global.dto.RsData;
import com.coffeebean.global.exception.DataNotFoundException;
import com.coffeebean.global.exception.ServiceException;
import com.coffeebean.global.security.annotations.AdminOnly;
import com.coffeebean.global.util.CustomUserDetails;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class OrderController {

    private final OrderService orderService;
    private final EmailVerificationService emailVerificationService;

    /**
     * 1. 전체 주문 내역 조회
     * GET /api/users/{email}/orders
     */
    @GetMapping("/my/orders")
    public ResponseEntity<List<OrderDto>> getAllOrders(@Login CustomUserDetails customUserDetails) {
        String email = customUserDetails.getEmail();
        List<OrderDto> orders = orderService.getOrdersByEmail(email);
        if (orders.isEmpty()) {
            throw new DataNotFoundException("해당 이메일로 주문 내역을 찾을 수 없습니다.");
        }
        return ResponseEntity.ok(orders);
    }

    /**
     * 2. 주문 상세 조회
     * GET /api/orders/{orderId}
     */
    @GetMapping("/orders/{orderId}")
    public ResponseEntity<OrderDetailDto> getOrderDetail(@Login CustomUserDetails customUserDetails, @PathVariable("orderId") Long orderId) {
        log.info("Received request for order ID: {}", orderId);
        OrderDetailDto order = orderService.getOrderDetailById(orderId);
        if (order == null) {
            throw new DataNotFoundException("해당 주문 번호를 찾을 수 없습니다.");
        }
        return ResponseEntity.ok(order);
    }

    /**
     * 3. 주문 취소
     * PUT /api/orders/{orderId}/cancel
     */
    @PutMapping("/orders/{orderId}/cancel")
    public ResponseEntity<?> cancelOrder(@PathVariable("orderId") Long orderId) {
        orderService.cancelOrder(orderId);
        return ResponseEntity.noContent().build();
    }

    // 비회원 주문 조회 - 이메일 인증
    @PostMapping("/v1/non-user/verify")
    public RsData<Void> nonUserEmailVerification(@RequestBody String email) {
        try {
            emailVerificationService.sendVerificationEmail(email);
            return new RsData<>("200-1", "인증번호가 이메일로 전송되었습니다.");
        } catch (Exception e) {
            throw new ServiceException("500-1", "이메일 발송 실패: " + e.getMessage());
        }
    }

    // 비회원 주문 조회 - 인증 완료
    @PostMapping("/v1/non-user/verify/true")
    public RsData<Void> verifyEmail(@RequestBody @Valid EmailVerificationRequest emailVerificationRequest) {
        boolean result = emailVerificationService.verifyEmailForGuest(emailVerificationRequest.getEmail(), emailVerificationRequest.getCode());
        log.info("컨트롤러 요청 데이터 -> email={}, code={}", emailVerificationRequest.getEmail(), emailVerificationRequest.getCode());
        if (!result) {
            throw new ServiceException("400-2", "이메일 인증 실패");
        }
        return new RsData<>("200-2", "이메일 인증 성공");
    }

    // 비회원 주문 조회 - 주문 리스트 반환
    @GetMapping("/v1/non-user/orders")
    public ResponseEntity<List<OrderDto>> getNonUserOrders(@RequestHeader("X-NonUser-Email") String email) {
        List<OrderDto> orders = orderService.getOrdersByEmail(email);
        if (orders.isEmpty()) {
            throw new DataNotFoundException("해당 이메일로 주문 내역을 찾을 수 없습니다.");
        }
        return ResponseEntity.ok(orders);
    }

    @GetMapping("/v1/non-user/orders/{orderId}")
    public ResponseEntity<OrderDetailDto> getNonUserOrderDetailDto(@PathVariable("orderId") Long orderId) {
        OrderDetailDto order = orderService.getOrderDetailById(orderId);
        if (order == null) {
            throw new DataNotFoundException("해당 주문 번호를 찾을 수 없습니다.");
        }
        return ResponseEntity.ok(order);
    }

    @PutMapping("/v1/non-user/orders/{orderId}/cancel")
    public ResponseEntity<?> cancelNonUserOrder(@PathVariable("orderId") Long orderId) {
        orderService.cancelOrder(orderId);
        return ResponseEntity.noContent().build();
    }

    // 관리자 - 주문 전체 조회
    @AdminOnly
    @GetMapping("/v1/orders/list")
    public RsData<OrderListResponseDto> getOrderList() {
        List<OrderListDto> orders = orderService.getAllOrder();

        return new RsData<>(
                "200-1",
                "주문 전체 조회 완료",
                new OrderListResponseDto(orders)
        );
    }


    // 관리자 - 주문 상세 보기
    @AdminOnly
    @GetMapping("/v1/orders/list/{id}")
    public RsData<OrderDetailDto> getOrderItem(@PathVariable long id) {
        OrderDetailDto orderDetail = orderService.getOrderDetailById(id);

        if (orderDetail == null) {
            throw new ServiceException("400-1", "해당 주문 번호를 찾을 수 없습니다.");
        }

        return new RsData<>(
                "200-2",
                "주문 상세 조회 완료",
                orderDetail
        );
    }

    record OrderStatusUpdateRequest(OrderStatus orderStatus) {}

    // 주문 상태 변경
    @AdminOnly
    @PatchMapping("/v1/orders/{orderId}/status")
    public ResponseEntity<String> updateOrderStatus(
            @PathVariable Long orderId,
            @RequestBody OrderStatusUpdateRequest request) {

        orderService.updateOrderStatus(orderId, request.orderStatus());
        return ResponseEntity.ok("주문 상태가 변경되었습니다.");
    }

    record DeliveryStatusUpdateRequest(DeliveryStatus deliveryStatus) {}

    // 배송 상태 변경
    @AdminOnly
    @PatchMapping("/v1/orders/{orderId}/delivery-status")
    public ResponseEntity<String> updateDeliveryStatus(
            @PathVariable Long orderId,
            @RequestBody DeliveryStatusUpdateRequest request) {

        orderService.updateDeliveryStatus(orderId, request.deliveryStatus());
        return ResponseEntity.ok("배송 상태가 변경되었습니다.");
    }
}