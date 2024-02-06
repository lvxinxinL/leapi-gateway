package com.ghost.leapigateway;

import com.ghost.leapiclientsdk.utils.SignUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author 乐小鑫
 * @version 1.0
 * @Date 2024-02-06-15:13
 */
@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 2. 请求日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("请求唯一标识：" + request.getId());
        log.info("请求路径：" + request.getPath().value());
        log.info("请求方法：" + request.getMethod());
        log.info("请求参数：" + request.getQueryParams());
        String sourceAddress = request.getLocalAddress().getHostString();
        log.info("请求来源地址：" + sourceAddress);
        log.info("请求来源地址：" + request.getRemoteAddress());
        // 3. 访问控制——（黑白名单）
        // 取到响应对象
        ServerHttpResponse response = exchange.getResponse();
        if (IP_WHITE_LIST.contains(sourceAddress)) {
            // 请求来源地址不在白名单中，无权限访问
            // 设置响应状态码
            return handleNoAuth(response);
        }
        // todo 4. 用户鉴权（判断 ak、sk 是否合法）
        // 获取请求头中携带的参数，校验调用接口的权限
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String body = headers.getFirst("body");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        // TODO 实际上要从数据库查是否已分配给用户
        if (!accessKey.equals("ghost")) {
            return handleNoAuth(response);
        }
        // 校验随机数
        if (Long.parseLong(nonce) > 100000) {
            return handleNoAuth(response);
        }

        // 校验时间戳 timestamp：和当前时间不能超过 5 min
        Long currentTime = System.currentTimeMillis() / 1000;
        final Long FIVE_MINUTES = 5 * 60L;
        if (currentTime - Long.parseLong(timestamp) >= FIVE_MINUTES) {
            return handleNoAuth(response);
        }
        // 和客户端使用同一套加密算法进行校验
        String serverSign = SignUtil.genSign(body, "abcdefg");// TODO 实际上要从数据库中取出数据进行校验
        if (!serverSign.equals(sign)) {
            return handleNoAuth(response);
        }
        // 5. todo 判断请求的模拟接口是否存在（从 leapi-backend 项目的数据库中查询）
        // 6. 请求转发，调用模拟接口
        Mono<Void> filter = chain.filter(exchange);
        log.info("响应：" + response.getStatusCode());
        // 7. 响应日志：编程式网关
        if (response.getStatusCode().equals(HttpStatus.OK)) {
            // 8. todo 调用成功，接口调用次数 + 1（leapi-backend 项目中已经写过了，到时候暴露出来使用）

        } else {
            // 9. 调用失败，返回规范错误码
            handleInvokeError(response);
        }
        log.info("custom global filter");
        return filter;
    }

    /**
     * 处理无权限调用
     * @param response
     * @return
     */
    private Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    /**
     * 处理调用失败
     * @param response
     * @return
     */
    private Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
