use crate::CheckResult;

/// 创建代理感知的 reqwest Client
fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());

    // 如果设置了全局代理，添加到客户端
    if let Some(ref proxy_url) = crate::get_global_proxy() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
        }
    }

    builder.build()
}

pub async fn http_get_check(
    ip: &str,
    port: u16,
    path: &str,
    keywords: &[&str],
    vuln_msg: &str,
    service: &str,
) -> CheckResult {
    let url = format!("http://{}:{}{}", ip, port, path);
    let client = match build_http_client()
    {
        Ok(c) => c,
        Err(e) => return CheckResult::Error(format!("创建 HTTP 客户端失败: {}", e)),
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status() == 200 => {
            let body = match resp.text().await {
                Ok(b) => b,
                Err(_) => return CheckResult::Secure("HTTP 响应读取失败".into()),
            };
            if keywords.iter().any(|k| body.contains(k)) {
                CheckResult::Vulnerable {
                    credentials: "无需认证".into(),
                    details: format!("{}: {}", vuln_msg, url),
                }
            } else {
                CheckResult::Secure(format!("{} 未发现未授权访问", service))
            }
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            if status == 401 || status == 403 {
                CheckResult::Secure(format!("{} 需要认证", service))
            } else {
                CheckResult::Secure(format!("{} 响应异常 (HTTP {})", service, status))
            }
        }
        Err(e) => {
            if e.is_connect() {
                CheckResult::Secure(format!("端口 {} 未开放", port))
            } else if e.is_timeout() {
                CheckResult::Error("连接超时".into())
            } else {
                CheckResult::Error(format!("请求失败: {}", e))
            }
        }
    }
}

pub async fn http_get_check_multi(
    ip: &str,
    port: u16,
    paths: &[&str],
    keywords: &[&str],
    vuln_msg: &str,
    service: &str,
) -> CheckResult {
    for path in paths {
        let result = http_get_check(ip, port, path, keywords, vuln_msg, service).await;
        if matches!(result, CheckResult::Vulnerable { .. }) {
            return result;
        }
    }
    CheckResult::Secure(format!("{} 未发现未授权访问", service))
}
