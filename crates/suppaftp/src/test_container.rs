#![allow(dead_code)]

use std::borrow::Cow;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use testcontainers::core::{CmdWaitFor, ContainerPort, ExecCommand, WaitFor};
use testcontainers::{Container, ContainerAsync, Image, ImageExt};

const TLS_SERVER_CERT_PATH: &str = "/etc/vsftpd/server-cert.pem";
const TLS_SERVER_KEY_PATH: &str = "/etc/vsftpd/server-key.pem";
const TLS_VSFTPD_CONFIG: &[u8] = br"anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
vsftpd_log_file=/proc/1/fd/1
ftpd_banner=Welcome Alpine ftp server https://hub.docker.com/r/delfer/alpine-ftp-server/
listen=YES
pasv_enable=YES
pasv_addr_resolve=YES
seccomp_sandbox=NO
background=YES
require_ssl_reuse=NO
ssl_tlsv12=YES
ssl_tlsv13=YES
";

#[derive(Debug, Default, Clone)]
struct AlpineFtpServer;

impl Image for AlpineFtpServer {
    fn name(&self) -> &str {
        "delfer/alpine-ftp-server"
    }

    fn tag(&self) -> &str {
        "latest"
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_either_std("passwd:")]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[
            ContainerPort::Tcp(21),
            ContainerPort::Tcp(30_000),
            ContainerPort::Tcp(30_001),
            ContainerPort::Tcp(30_002),
            ContainerPort::Tcp(30_003),
            ContainerPort::Tcp(30_004),
            ContainerPort::Tcp(30_005),
            ContainerPort::Tcp(30_006),
            ContainerPort::Tcp(30_007),
            ContainerPort::Tcp(30_008),
            ContainerPort::Tcp(30_009),
        ]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        vec![
            ("USERS", "test|test|/home/test"),
            ("ADDRESS", "127.0.0.1"),
            ("MIN_PORT", "30000"),
            ("MAX_PORT", "30009"),
        ]
    }
}

#[derive(Debug, Default, Clone)]
struct TlsAlpineFtpServer;

impl Image for TlsAlpineFtpServer {
    fn name(&self) -> &str {
        "delfer/alpine-ftp-server"
    }

    fn tag(&self) -> &str {
        "latest"
    }

    fn ready_conditions(&self) -> Vec<WaitFor> {
        vec![WaitFor::message_on_either_std("passwd:")]
    }

    fn expose_ports(&self) -> &[ContainerPort] {
        &[
            ContainerPort::Tcp(21),
            ContainerPort::Tcp(30_000),
            ContainerPort::Tcp(30_001),
            ContainerPort::Tcp(30_002),
            ContainerPort::Tcp(30_003),
            ContainerPort::Tcp(30_004),
            ContainerPort::Tcp(30_005),
            ContainerPort::Tcp(30_006),
            ContainerPort::Tcp(30_007),
            ContainerPort::Tcp(30_008),
            ContainerPort::Tcp(30_009),
        ]
    }

    fn env_vars(
        &self,
    ) -> impl IntoIterator<Item = (impl Into<Cow<'_, str>>, impl Into<Cow<'_, str>>)> {
        vec![
            ("USERS", "test|test|/home/test"),
            ("ADDRESS", "127.0.0.1"),
            ("MIN_PORT", "30000"),
            ("MAX_PORT", "30009"),
        ]
    }
}

fn tls_ftp_image() -> impl Into<testcontainers::ContainerRequest<TlsAlpineFtpServer>> {
    TlsAlpineFtpServer
        .with_copy_to("/etc/vsftpd/vsftpd.conf", TLS_VSFTPD_CONFIG.to_vec())
        .with_copy_to(
            TLS_SERVER_CERT_PATH,
            include_bytes!("test_container/fixtures/server-cert.pem").to_vec(),
        )
        .with_copy_to(
            TLS_SERVER_KEY_PATH,
            include_bytes!("test_container/fixtures/server-key.pem").to_vec(),
        )
        .with_env_var("TLS_CERT", TLS_SERVER_CERT_PATH)
        .with_env_var("TLS_KEY", TLS_SERVER_KEY_PATH)
}

fn wait_for_ftp_listener(port: u16) {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let last_result = match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .expect("Failed to set FTP readiness timeout");
                let mut reader = BufReader::new(stream);
                let mut greeting = String::new();
                match reader.read_line(&mut greeting) {
                    Ok(_) if greeting.starts_with("220 ") => return,
                    Ok(_) => format!("received {greeting:?}"),
                    Err(error) => error.to_string(),
                }
            }
            Err(error) => error.to_string(),
        };

        if Instant::now() >= deadline {
            panic!("FTP listener on {address} did not send a 220 greeting: {last_result}");
        }

        thread::sleep(Duration::from_millis(50));
    }
}

fn prepare_tls_server(container: &Container<TlsAlpineFtpServer>) {
    let directory = "/home/test/readonly";
    let commands = [
        ["/bin/mkdir", directory, ""],
        ["/bin/chown", "root:root", directory],
        ["/bin/chmod", "0555", directory],
    ];

    for command in commands {
        let args = command.into_iter().filter(|arg| !arg.is_empty());
        let response = container
            .exec(
                ExecCommand::new(args).with_cmd_ready_condition(CmdWaitFor::Exit { code: Some(0) }),
            )
            .expect("Failed to prepare TLS server");
        assert_eq!(
            response
                .exit_code()
                .expect("failed to get exit code for TLS server setup")
                .expect("no exit code for TLS server setup"),
            0
        );
    }
}

async fn prepare_async_tls_server(container: &ContainerAsync<TlsAlpineFtpServer>) {
    let directory = "/home/test/readonly";
    let commands = [
        ["/bin/mkdir", directory, ""],
        ["/bin/chown", "root:root", directory],
        ["/bin/chmod", "0555", directory],
    ];

    for command in commands {
        let args = command.into_iter().filter(|arg| !arg.is_empty());
        let response = container
            .exec(
                ExecCommand::new(args).with_cmd_ready_condition(CmdWaitFor::Exit { code: Some(0) }),
            )
            .await
            .expect("Failed to prepare TLS server");
        assert_eq!(
            response
                .exit_code()
                .await
                .expect("failed to get exit code for TLS server setup")
                .expect("no exit code for TLS server setup"),
            0
        );
    }
}

pub struct SyncTlsFtpRunner {
    container: Container<TlsAlpineFtpServer>,
}

impl SyncTlsFtpRunner {
    pub fn start() -> Self {
        use testcontainers::runners::SyncRunner;

        let container = tls_ftp_image()
            .start()
            .expect("Failed to start TLS FTP container");
        let port = container.get_host_port_ipv4(21).unwrap();
        wait_for_ftp_listener(port);
        prepare_tls_server(&container);

        Self { container }
    }

    pub fn get_ftp_port(&self) -> u16 {
        self.container.get_host_port_ipv4(21).unwrap()
    }

    pub fn get_mapped_port(&self, port: u16) -> u16 {
        self.container.get_host_port_ipv4(port).unwrap()
    }
}

pub struct AsyncTlsFtpRunner {
    container: ContainerAsync<TlsAlpineFtpServer>,
}

impl AsyncTlsFtpRunner {
    pub async fn start() -> Self {
        use testcontainers::runners::AsyncRunner;

        let container = tls_ftp_image()
            .start()
            .await
            .expect("Failed to start TLS FTP container");
        let port = container.get_host_port_ipv4(21).await.unwrap();
        wait_for_ftp_listener(port);
        prepare_async_tls_server(&container).await;

        Self { container }
    }

    pub async fn get_ftp_port(&self) -> u16 {
        self.container.get_host_port_ipv4(21).await.unwrap()
    }

    pub async fn get_mapped_port(&self, port: u16) -> u16 {
        self.container.get_host_port_ipv4(port).await.unwrap()
    }
}

pub struct AsyncPureFtpRunner {
    container: ContainerAsync<AlpineFtpServer>,
}

impl AsyncPureFtpRunner {
    pub async fn start() -> Self {
        use testcontainers::runners::AsyncRunner;
        let container = AlpineFtpServer
            .start()
            .await
            .expect("Failed to start container");
        let resp = container
            .exec(
                ExecCommand::new(["/bin/mkdir", "-p", "/home/test/invalid-utf8"])
                    .with_cmd_ready_condition(CmdWaitFor::Exit { code: Some(0) }),
            )
            .await
            .expect("Failed to create directory");
        assert_eq!(
            resp.exit_code()
                .await
                .expect("failed to get exit code for mkdir")
                .expect("no exit code for mkdir"),
            0
        );
        let resp = container
            .exec(
                ExecCommand::new(["/bin/touch", "/home/test/invalid-utf8/caf\\303\\251.txt"])
                    .with_cmd_ready_condition(CmdWaitFor::Exit { code: Some(0) }),
            )
            .await
            .expect("Failed to create file");
        assert_eq!(
            resp.exit_code()
                .await
                .expect("failed to get exit code for touch")
                .expect("no exit code for touch"),
            0
        );
        Self { container }
    }

    pub async fn get_ftp_port(&self) -> u16 {
        self.container.get_host_port_ipv4(21).await.unwrap()
    }

    pub async fn get_mapped_port(&self, port: u16) -> u16 {
        self.container.get_host_port_ipv4(port).await.unwrap()
    }
}

pub struct SyncPureFtpRunner {
    container: Container<AlpineFtpServer>,
}

impl SyncPureFtpRunner {
    pub fn start() -> Self {
        use testcontainers::runners::SyncRunner;
        let container = AlpineFtpServer.start().expect("Failed to start container");

        let resp = container
            .exec(
                ExecCommand::new(["/bin/mkdir", "-p", "/home/test/invalid-utf8"])
                    .with_cmd_ready_condition(CmdWaitFor::Exit { code: Some(0) }),
            )
            .expect("Failed to create directory");
        assert_eq!(
            resp.exit_code()
                .expect("failed to get exit code for mkdir")
                .expect("no exit code for mkdir"),
            0
        );
        let resp = container
            .exec(
                ExecCommand::new(["/bin/touch", "/home/test/invalid-utf8/caf\\303\\251.txt"])
                    .with_cmd_ready_condition(CmdWaitFor::Exit { code: Some(0) }),
            )
            .expect("Failed to create file");
        assert_eq!(
            resp.exit_code()
                .expect("failed to get exit code for touch")
                .expect("no exit code for touch"),
            0
        );

        Self { container }
    }

    pub fn get_ftp_port(&self) -> u16 {
        self.container.get_host_port_ipv4(21).unwrap()
    }

    pub fn get_mapped_port(&self, port: u16) -> u16 {
        self.container.get_host_port_ipv4(port).unwrap()
    }
}
