# Ecommerce Authentication Service

Project Spring Boot dùng Java 17, Maven và package gốc `com.d10g.ecommerce_auth`. Yêu cầu và tiêu chí nghiệm thu nằm trong [đặc tả](docs/authentication-service-spec.md).

## Trạng thái triển khai

Project có API tài khoản, OTP, Google, quản lý session và introspection nội bộ, cùng PostgreSQL, Redis và worker email. API chỉ được kích hoạt khi `auth.runtime.enabled=true` và các khóa, client registrations, origin và worker được cấu hình. Xem [hợp đồng API](docs/openapi.json), [hướng dẫn tích hợp](docs/client-integration.md), [email outbox](docs/email-outbox.md) và [introspection](docs/internal-introspection.md).

Trước khi sử dụng production cần hoàn tất kiểm thử nghiệm thu trên môi trường triển khai, gồm mTLS, Google SDK thật, nhiều instance, dependency outage, benchmark và backup/restore theo đặc tả. Cấu hình local trong Compose không thay thế các yêu cầu vận hành production.

## Chạy kiểm thử

Dùng JDK 17 và Maven wrapper:

```sh
./mvnw test
```

`contextLoads` cần PostgreSQL tại `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`. Test JDBC session tạo schema tạm và chạy khi đặt `AUTH_TEST_DB_URL`, `AUTH_TEST_DB_USER`, `AUTH_TEST_DB_PASSWORD`; database test phải cho phép tạo và xóa schema. Không trỏ biến test tới database chứa dữ liệu quan trọng.

Để chạy hạ tầng local, cung cấp `DB_PASSWORD` trong môi trường hoặc file `.env` local rồi chạy `docker compose up --build`. Compose chỉ dành cho phát triển; không dùng giá trị secret production và không mở các cổng local ra mạng công cộng. Thiết lập TLS, khóa và credentials production bên ngoài repository theo đặc tả.
