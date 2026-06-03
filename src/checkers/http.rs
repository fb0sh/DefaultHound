use crate::prelude::*;

pub struct HttpChecker;

#[async_trait]
impl ServiceChecker for HttpChecker {
    fn service_name(&self) -> &'static str {
        "HTTP"
    }

    fn default_port(&self) -> u16 {
        80
    }

    fn default_credentials(&self) -> Vec<Credential> {
        vec![
            Credential::new("admin", "admin"),
            Credential::new("admin", ""),
            Credential::new("admin", "123456"),
            Credential::new("root", ""),
            Credential::new("root", "root"),
            Credential::new("tomcat", "tomcat"),
            Credential::new("user", "user"),
        ]
    }

    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());
        let base_url = format!("http://{}:{}", ip, port);

        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
        {
            Ok(c) => c,
            Err(e) => return CheckResult::Error(format!("创建 HTTP 客户端失败: {}", e)),
        };

        let admin_paths = ["/admin", "/login", "/manager/html", "/wp-admin"];

        for path in &admin_paths {
            let url = format!("{}{}", base_url, path);

            match client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    let www_auth = resp
                        .headers()
                        .get(reqwest::header::WWW_AUTHENTICATE)
                        .and_then(|v| v.to_str().ok());

                    if status == reqwest::StatusCode::UNAUTHORIZED {
                        if let Some(auth_header) = www_auth {
                            if auth_header.to_lowercase().contains("basic") {
                                for cred in HttpChecker.default_credentials() {
                                    match client
                                        .get(&url)
                                        .basic_auth(cred.username.as_ref(), Some(cred.password.as_ref()))
                                        .send()
                                        .await
                                    {
                                        Ok(auth_resp) => {
                                            if auth_resp.status().is_success() {
                                                return CheckResult::Vulnerable {
                                                    credentials: cred.display(),
                                                    details: format!(
                                                        "Basic Auth 凭据有效，可访问 {}",
                                                        url
                                                    ),
                                                };
                                            }
                                        }
                                        Err(_) => continue,
                                    }
                                }
                            }
                        }
                    } else if status.is_success() {
                        return CheckResult::Vulnerable {
                            credentials: "无需认证".to_string(),
                            details: format!(
                                "{} 无需登录即可访问 (HTTP {})",
                                url,
                                status.as_u16()
                            ),
                        };
                    }
                }
                Err(e) => {
                    if e.is_connect() {
                        return CheckResult::Secure(format!("端口 {} 未开放", port));
                    }
                    continue;
                }
            }
        }

        CheckResult::Secure("HTTP 服务运行中，未发现可用的默认凭据".to_string())
    }
}
