use crate::prelude::*;

pub struct NacosWeakpassChecker;

#[async_trait]
impl ServiceChecker for NacosWeakpassChecker {
    fn service_name(&self) -> &'static str {
        "NacosWeakpass"
    }

    fn default_port(&self) -> u16 {
        8848
    }
    fn proto(&self) -> &'static str {
        "http"
    }


    fn default_credentials(&self) -> Vec<Credential> {
        vec![Credential::new("nacos", "nacos")]
    }

    async fn check(&self, ip: &str, port: Option<u16>) -> CheckResult {
        let port = port.unwrap_or(self.default_port());

        for cred in self.default_credentials() {
            let url = format!("http://{}:{}/nacos/v1/auth/login", ip, port);

            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    return CheckResult::Error(format!("创建 HTTP 客户端失败: {}", e));
                }
            };

            let params = [
                ("username", cred.username.as_ref()),
                ("password", cred.password.as_ref()),
            ];

            match client.post(&url).form(&params).send().await {
                Ok(resp) if resp.status() == 200 => {
                    let body = match resp.text().await {
                        Ok(b) => b,
                        Err(_) => return CheckResult::Secure("HTTP 响应读取失败".into()),
                    };
                    // 登录成功返回 {"accessToken":"xxx","tokenTtl":xxx,"globalAdmin":true}
                    if body.contains("accessToken") {
                        return CheckResult::Vulnerable {
                            credentials: cred.display(),
                            details: format!("Nacos 弱密码: {}:{}", cred.username, cred.password),
                        };
                    }
                }
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 401 || status == 403 {
                        continue;
                    } else if status == 302 {
                        // Nacos 旧版本可能返回 302 重定向到登录页
                        continue;
                    } else {
                        return CheckResult::Secure(format!("Nacos 响应异常 (HTTP {})", status));
                    }
                }
                Err(e) => {
                    if e.is_connect() {
                        return CheckResult::Secure(format!("端口 {} 未开放", port));
                    } else if e.is_timeout() {
                        return CheckResult::Error("连接超时".into());
                    } else {
                        return CheckResult::Error(format!("请求失败: {}", e));
                    }
                }
            }
        }

        CheckResult::Secure("Nacos 未发现弱密码".into())
    }
}
