# Kiểm tra phiên từ service nội bộ

Bật `auth.internal.enabled=true` cùng `auth.internal.client-certificate-sha256`, danh sách fingerprint SHA-256 dạng hex của leaf certificate client được phép, phân tách bằng dấu phẩy. Inject danh sách từ cấu hình môi trường. Endpoint `POST /internal/v1/auth/introspect` nhận `{ "token": "..." }`.

Auth Service phải trực tiếp kết thúc TLS và cấu hình trust store cùng `server.ssl.client-auth=want` hoặc `need` để servlet container yêu cầu và xác thực chứng chỉ client. Nếu dùng `want`, fingerprint đã cấu hình giới hạn caller của endpoint nội bộ; endpoint vẫn từ chối khi không có chứng chỉ hợp lệ. Giới hạn truy cập bằng mạng nội bộ. Không dùng forwarded certificate header: server kiểm tra chứng chỉ được TLS container cung cấp, đồng thời ghim fingerprint và kiểm tra hạn hiệu lực.

Token không hợp lệ trả `200` với `active=false`; token hợp lệ trả thêm `user_id`, `session_id`, `expires_at`. Lỗi database trả `503`. Resource server phải kiểm tra JWT RS256, issuer, audience, expiry và JWKS trước, sau đó gọi introspection cho từng request; không cache kết quả active, dùng timeout một giây, không retry đồng bộ, trả `503` khi không liên lạc được Auth Service. Không ghi token vào log.
