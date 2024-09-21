use std::env;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use crate::logger::Logger;
use crate::{error, info};

#[derive(Debug, Clone)]
struct RequestParams {
    host: String,
    path: String,
    port: u16,
    model: String,
    authorization_token: String,
}

fn encode_base64(filepath: &str) -> Result<String, std::io::Error> {
    let mut file = std::fs::File::open(filepath)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    Ok(base64::encode(&buffer))
}

pub fn annotate(filename: String) -> Result<String, std::io::Error> {
    let params = RequestParams {
        host: "api.openai.com".to_string(),
        path: "/v1/chat/completions".to_string(),
        port: 443,
        model: "gpt-4o-mini".to_string(),
        authorization_token: env::var("OPENAI_API_KEY")
            .expect("OPENAI_API_KEY environment variable not set"),
    };

    let image_bytes = encode_base64(&filename)?;

    let duration = std::time::Duration::from_secs(30);
    let address = (params.host.clone(), params.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            error!(
                "Failed to resolve address {:?}",
                (params.host.clone(), params.port)
            );
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Failed to resolve address",
            )
        })?;

    let stream = match TcpStream::connect_timeout(&address, duration) {
        Ok(stream) => stream,
        Err(e) => {
            error!("Failed to connect to OpenAI API: {:?}", e);
            return Err(e);
        }
    };

    match stream.set_read_timeout(Some(duration)) {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to set read timeout: {:?}", e);
            return Err(e);
        }
    }

    match stream.set_write_timeout(Some(duration)) {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to set write timeout: {:?}", e);
            return Err(e);
        }
    }

    let connector = native_tls::TlsConnector::new().expect("Failed to create TLS connector");
    let mut stream = connector
        .connect(&params.host, stream)
        .expect("Failed to establish TLS connection");

    let body = serde_json::json!({
        "model": params.model,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                            "text": "Can you annotate and transcribe this image? Please respond with just the annotation and transcription, and use markdown if it's applicable. When encountering typos in the transcription, feel at liberty to correct them to make the most sense of what is being written."
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": format!("data:image/jpeg;base64,{}", image_bytes)
                        }
                    }
                ]
            },
        ]
    });
    let json = serde_json::json!(body);
    let json_string = serde_json::to_string(&json)?;

    let auth_string = "Authorization: Bearer ".to_string() + &params.authorization_token;

    let request = format!(
        "POST {} HTTP/1.1\r\n\
        Host: {}\r\n\
        Content-Type: application/json\r\n\
        Content-Length: {}\r\n\
        Accept: */*\r\n\
        {}\r\n\r\n\
        {}",
        params.path,
        params.host,
        json_string.len(),
        auth_string,
        json_string.trim()
    );

    match stream.write_all(request.as_bytes()) {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to write to OpenAI stream: {:?}", e);
            return Err(e);
        }
    }

    match stream.flush() {
        Ok(_) => (),
        Err(e) => {
            error!("Failed to flush OpenAI stream: {:?}", e);
            return Err(e);
        }
    }

    let mut reader = std::io::BufReader::new(&mut stream);

    let mut buffer = String::new();
    // read 2 characters at a time to check for CRLF
    while !buffer.ends_with("\r\n\r\n") {
        let mut chunk = [0; 1];
        match reader.read(&mut chunk) {
            Ok(0) => {
                error!("Failed to read from OpenAI stream: EOF");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Failed to read from OpenAI stream",
                ));
            }
            Ok(_) => {
                buffer.push_str(&String::from_utf8_lossy(&chunk));
            }
            Err(e) => {
                error!("Failed to read from OpenAI stream: {:?}", e);
                return Err(e);
            }
        }
    }

    let headers = buffer.split("\r\n").collect::<Vec<&str>>();
    let content_length = headers
        .iter()
        .find(|header| header.starts_with("Content-Length"))
        .ok_or_else(|| {
            error!("Failed to find Content-Length header: {:?}", headers);
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to find Content-Length header",
            )
        })?;

    let content_length = content_length.split(": ").collect::<Vec<&str>>()[1]
        .parse::<usize>()
        .unwrap();

    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;

    let body = String::from_utf8_lossy(&body).to_string();
    let response_json = serde_json::from_str(&body);

    if response_json.is_err() {
        error!("Failed to parse JSON: {}", body);
        error!("Headers: {}", headers.join("\n"));
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse JSON",
        ));
    }

    let response_json: serde_json::Value = response_json.unwrap();
    let data = match response_json["choices"][0]["message"]["content"].as_str() {
        Some(data) => data,
        _ => {
            error!("Failed to parse data from JSON:\n{:?}", response_json);
            error!("Response: {}", body);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to parse data from JSON",
            ));
        }
    };

    let total_tokens = match response_json["usage"]["total_tokens"].as_u64() {
        Some(tokens) => tokens,
        _ => {
            error!(
                "Failed to parse total tokens from JSON:\n{:?}",
                response_json
            );
            error!("Response: {}", body);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Failed to parse total tokens from JSON",
            ));
        }
    };

    info!(
        "finished openai request with total tokens: {}",
        total_tokens
    );

    Ok(data.to_string())
}
