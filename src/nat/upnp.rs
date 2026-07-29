#[derive(Clone, Debug)]
pub struct UPnPMapping {
    pub igd_host: String,
    pub igd_port: u16,
    pub ctrl_path: String,
    pub svc_type: String,
    pub ext_port: u16,
    pub external_ip: String,
    pub local_ip: String,
    pub description: String,
}

pub async fn discover_and_add_port(local_ip: &str, port: u16, desc: &str) -> Option<UPnPMapping> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let req = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 2\r\n",
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    );
    let _ = sock
        .send_to(req.as_bytes(), "239.255.255.250:1900")
        .await
        .ok()?;
    let mut buf = [0u8; 2048];
    let (n, _from) =
        tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();
    let location = resp
        .lines()
        .find_map(|l| {
            l.strip_prefix("LOCATION: ")
                .or_else(|| l.strip_prefix("Location: "))
        })?
        .trim()
        .to_string();
    let (igd_host, igd_port, path) = parse_location(&location)?;
    let host = format!("{igd_host}:{igd_port}");
    let xml = http_get(&host, &path).await?;
    let ctrl_path = extract_tag(&xml, "controlURL").unwrap_or("/upnp/control".to_string());
    let svc_type = extract_tag(&xml, "serviceType")
        .unwrap_or("urn:schemas-upnp-org:service:WANIPConnection:1".to_string());

    let soap = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:AddPortMapping xmlns:u="{svc_type}">
   <NewRemoteHost></NewRemoteHost>
   <NewExternalPort>{port}</NewExternalPort>
   <NewProtocol>UDP</NewProtocol>
   <NewInternalPort>{port}</NewInternalPort>
   <NewInternalClient>{local_ip}</NewInternalClient>
   <NewEnabled>1</NewEnabled>
   <NewPortMappingDescription>{desc}</NewPortMappingDescription>
   <NewLeaseDuration>600</NewLeaseDuration>
  </u:AddPortMapping>
 </s:Body>
</s:Envelope>"#
    );
    let _ = http_soap_post(&host, &ctrl_path, &svc_type, "AddPortMapping", &soap).await?;
    let external_ip = query_external_ip(&host, &ctrl_path, &svc_type)
        .await
        .unwrap_or_else(|| local_ip.to_string());
    Some(UPnPMapping {
        igd_host,
        igd_port,
        ctrl_path,
        svc_type,
        ext_port: port,
        external_ip,
        local_ip: local_ip.to_string(),
        description: desc.to_string(),
    })
}

pub async fn remove_port(mapping: &UPnPMapping) {
    let soap = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:DeletePortMapping xmlns:u="{svc}">
   <NewRemoteHost></NewRemoteHost>
   <NewExternalPort>{port}</NewExternalPort>
   <NewProtocol>UDP</NewProtocol>
  </u:DeletePortMapping>
 </s:Body>
</s:Envelope>"#,
        svc = mapping.svc_type,
        port = mapping.ext_port
    );
    let host = format!("{}:{}", mapping.igd_host, mapping.igd_port);
    let _ = http_soap_post(
        &host,
        &mapping.ctrl_path,
        &mapping.svc_type,
        "DeletePortMapping",
        &soap,
    )
    .await;
}

pub async fn refresh_port(mapping: &UPnPMapping) -> bool {
    let host = format!("{}:{}", mapping.igd_host, mapping.igd_port);
    let soap = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:AddPortMapping xmlns:u="{svc_type}">
   <NewRemoteHost></NewRemoteHost>
   <NewExternalPort>{port}</NewExternalPort>
   <NewProtocol>UDP</NewProtocol>
   <NewInternalPort>{port}</NewInternalPort>
   <NewInternalClient>{local_ip}</NewInternalClient>
   <NewEnabled>1</NewEnabled>
   <NewPortMappingDescription>{desc}</NewPortMappingDescription>
   <NewLeaseDuration>600</NewLeaseDuration>
  </u:AddPortMapping>
 </s:Body>
</s:Envelope>"#,
        svc_type = mapping.svc_type,
        port = mapping.ext_port,
        local_ip = mapping.local_ip,
        desc = mapping.description,
    );
    http_soap_post(
        &host,
        &mapping.ctrl_path,
        &mapping.svc_type,
        "AddPortMapping",
        &soap,
    )
    .await
    .is_some()
}

fn parse_location(location: &str) -> Option<(String, u16, String)> {
    let no_http = location.strip_prefix("http://")?;
    let (authority, path) = no_http.split_once('/').unwrap_or((no_http, ""));
    let (host, port) = if let Some(inner) = authority
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
    {
        (inner.to_string(), 80)
    } else if authority.starts_with('[') {
        let end = authority.find(']')?;
        let host = authority[1..end].to_string();
        let rest = &authority[end + 1..];
        if let Some(port) = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
            (host, port)
        } else {
            (host, 80)
        }
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if let Ok(parsed_port) = port.parse::<u16>() {
            (host.to_string(), parsed_port)
        } else {
            (authority.to_string(), 80)
        }
    } else {
        (authority.to_string(), 80)
    };
    Some((host, port, format!("/{}", path)))
}

async fn http_get(host: &str, path: &str) -> Option<String> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(host),
    )
    .await
    .ok()?
    .ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.write_all(req.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    let resp = String::from_utf8_lossy(&buf);
    Some(resp.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

async fn http_soap_post(
    host: &str,
    path: &str,
    svc_type: &str,
    action: &str,
    body: &str,
) -> Option<String> {
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(host),
    )
    .await
    .ok()?
    .ok()?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{svc_type}#{action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.write_all(req.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;
    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_to_end(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&close)? + s;
    Some(xml[s..e].trim().to_string())
}

async fn query_external_ip(host: &str, path: &str, svc_type: &str) -> Option<String> {
    let soap = format!(
        r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <s:Body>
  <u:GetExternalIPAddress xmlns:u="{svc_type}"></u:GetExternalIPAddress>
 </s:Body>
</s:Envelope>"#
    );
    let resp = http_soap_post(host, path, svc_type, "GetExternalIPAddress", &soap).await?;
    extract_tag(&resp, "NewExternalIPAddress")
}

#[cfg(test)]
mod tests {
    use super::parse_location;

    #[test]
    fn parse_location_with_explicit_port() {
        let (host, port, path) = parse_location("http://192.168.1.1:49152/rootDesc.xml").unwrap();
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 49152);
        assert_eq!(path, "/rootDesc.xml");
    }

    #[test]
    fn parse_location_without_port_defaults_80() {
        let (host, port, path) = parse_location("http://router.local/rootDesc.xml").unwrap();
        assert_eq!(host, "router.local");
        assert_eq!(port, 80);
        assert_eq!(path, "/rootDesc.xml");
    }
}
