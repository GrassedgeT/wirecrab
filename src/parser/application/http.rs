
//! HTTP协议解析模块
//! 
//! 支持解析HTTP请求和响应数据。

use super::ApplicationLayer;
use anyhow::{bail, Result};
use std::collections::HashMap;

/// 解析HTTP数据
pub fn parse_http_data(data: &[u8]) -> Result<ApplicationLayer> {
    // 尝试将数据转换为字符串
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // 如果不是有效的UTF-8，可能是二进制数据
            bail!("HTTP数据包含无效的UTF-8字符");
        }
    };

    // 检查是请求还是响应
    if text.starts_with("HTTP/") {
        parse_http_response(text)
    } else if is_http_method(&text[..text.find(' ').unwrap_or(text.len())]) {
        parse_http_request(text)
    } else {
        bail!("无法识别的HTTP数据格式");
    }
}

/// 检查是否是有效的HTTP方法
fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT" | "PATCH"
    )
}

/// 解析HTTP请求
fn parse_http_request(text: &str) -> Result<ApplicationLayer> {
    let mut lines = text.lines();
    
    // 解析请求行
    let request_line = lines.next().ok_or_else(|| anyhow::anyhow!("HTTP请求缺少请求行"))?;
    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() < 3 {
        bail!("HTTP请求行格式错误");
    }
    
    let method = parts[0].to_string();
    let uri = parts[1].to_string();
    let version = parts[2].to_string();

    // 解析头部
    let (headers, body_start) = parse_headers(&mut lines)?;
    
    // 解析请求体预览
    let body_preview = if body_start {
        let body_lines: Vec<&str> = lines.collect();
        if !body_lines.is_empty() {
            let body = body_lines.join("\n");
            Some(truncate_body(&body, 1024)) // 限制预览长度
        } else {
            None
        }
    } else {
        None
    };

    Ok(ApplicationLayer::HTTP {
        method: Some(method),
        uri: Some(uri),
        version,
        status_code: None,
        headers,
        body_preview,
    })
}

/// 解析HTTP响应
fn parse_http_response(text: &str) -> Result<ApplicationLayer> {
    let mut lines = text.lines();
    
    // 解析状态行
    let status_line = lines.next().ok_or_else(|| anyhow::anyhow!("HTTP响应缺少状态行"))?;
    let parts: Vec<&str> = status_line.split(' ').collect();
    if parts.len() < 2 {
        bail!("HTTP状态行格式错误");
    }
    
    let version = parts[0].to_string();
    let status_code = parts[1].parse::<u16>()
        .map_err(|_| anyhow::anyhow!("无效的HTTP状态码"))?;

    // 解析头部
    let (headers, body_start) = parse_headers(&mut lines)?;
    
    // 解析响应体预览
    let body_preview = if body_start {
        let body_lines: Vec<&str> = lines.collect();
        if !body_lines.is_empty() {
            let body = body_lines.join("\n");
            Some(truncate_body(&body, 1024)) // 限制预览长度
        } else {
            None
        }
    } else {
        None
    };

    Ok(ApplicationLayer::HTTP {
        method: None,
        uri: None,
        version,
        status_code: Some(status_code),
        headers,
        body_preview,
    })
}

/// 解析HTTP头部
fn parse_headers(lines: &mut std::str::Lines) -> Result<(HashMap<String, String>, bool)> {
    let mut headers = HashMap::new();
    let mut body_start = false;
    
    for line in lines {
        if line.is_empty() {
            // 空行表示头部结束，后面是正文
            body_start = true;
            break;
        }
        
        // 解析头部字段
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_lowercase();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.insert(name, value);
        } else if line.starts_with(' ') || line.starts_with('\t') {
            // 这是上一个头部字段的续行
            // HTTP/1.1允许头部字段值跨多行
            continue;
        } else {
            // 无效的头部行
            bail!("无效的HTTP头部行: {}", line);
        }
    }
    
    Ok((headers, body_start))
}

/// 截断正文内容以便预览
fn truncate_body(body: &str, max_len: usize) -> String {
    if body.len() <= max_len {
        body.to_string()
    } else {
        format!("{}...[truncated]", &body[..max_len])
    }
}

/// 获取HTTP状态码的描述
pub fn get_status_description(code: u16) -> &'static str {
    match code {
        // 1xx 信息性状态码
        100 => "Continue",
        101 => "Switching Protocols",
        
        // 2xx 成功状态码
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        
        // 3xx 重定向状态码
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        
        // 4xx 客户端错误状态码
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        429 => "Too Many Requests",
        
        // 5xx 服务器错误状态码
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_method() {
        assert!(is_http_method("GET"));
        assert!(is_http_method("POST"));
        assert!(!is_http_method("INVALID"));
    }

    #[test]
    fn test_parse_http_request() {
        let request = "GET /index.html HTTP/1.1\r\n\
                      Host: example.com\r\n\
                      User-Agent: Test/1.0\r\n\
                      \r\n";
        
        let result = parse_http_data(request.as_bytes()).unwrap();
        
        if let ApplicationLayer::HTTP { method, uri, version, headers, .. } = result {
            assert_eq!(method, Some("GET".to_string()));
            assert_eq!(uri, Some("/index.html".to_string()));
            assert_eq!(version, "HTTP/1.1");
            assert_eq!(headers.get("host"), Some(&"example.com".to_string()));
            assert_eq!(headers.get("user-agent"), Some(&"Test/1.0".to_string()));
        } else {
            panic!("Expected HTTP request");
        }
    }

    #[test]
    fn test_parse_http_response() {
        let response = "HTTP/1.1 200 OK\r\n\
                       Content-Type: text/html\r\n\
                       Content-Length: 13\r\n\
                       \r\n\
                       Hello, World!";
        
        let result = parse_http_data(response.as_bytes()).unwrap();
        
        if let ApplicationLayer::HTTP { version, status_code, headers, body_preview, .. } = result {
            assert_eq!(version, "HTTP/1.1");
            assert_eq!(status_code, Some(200));
            assert_eq!(headers.get("content-type"), Some(&"text/html".to_string()));
            assert_eq!(headers.get("content-length"), Some(&"13".to_string()));
            assert_eq!(body_preview, Some("Hello, World!".to_string()));
        } else {
            panic!("Expected HTTP response");
        }
    }
#[test]
fn test_get_status_description() {
    assert_eq!(get_status_description(200), "OK");
    assert_eq!(get_status_description(404), "Not Found");
    assert_eq!(get_status_description(500), "Internal Server Error");
    assert_eq!(get_status_description(999), "Unknown");
}
}
    

