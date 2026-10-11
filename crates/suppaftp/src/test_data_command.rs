//! Bounded FTP control and data server used to assert transfer startup ordering.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::status::Status;
use crate::types::Mode;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// A scripted FTP server for transfer-startup ordering tests.
pub(crate) struct ScriptedDataServer {
    address: SocketAddr,
    cancelled: Arc<AtomicBool>,
    control_stream: Arc<Mutex<Option<TcpStream>>>,
    worker: Option<JoinHandle<Result<(), String>>>,
}

impl ScriptedDataServer {
    /// Starts a server that replies to the transfer command with `reply`.
    pub(crate) fn start(mode: Mode, reply: Status) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind scripted FTP server");
        listener
            .set_nonblocking(true)
            .expect("make scripted FTP listener nonblocking");
        let address = listener.local_addr().expect("read scripted FTP address");
        let cancelled = Arc::new(AtomicBool::new(false));
        let control_stream = Arc::new(Mutex::new(None));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_control = Arc::clone(&control_stream);
        let worker_shutdown = Arc::clone(&control_stream);
        let worker = thread::spawn(move || {
            let _shutdown_on_exit = ShutdownControlOnExit(worker_shutdown);
            serve(listener, mode, reply, worker_cancelled, worker_control)
        });

        Self {
            address,
            cancelled,
            control_stream,
            worker: Some(worker),
        }
    }

    /// Returns the address clients should connect to.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Joins the server and reports any protocol or socket failure.
    pub(crate) fn finish(mut self) {
        let worker = self.worker.take().expect("server worker already joined");
        worker
            .join()
            .expect("scripted FTP server panicked")
            .expect("scripted FTP server failed");
    }
}

impl Drop for ScriptedDataServer {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::SeqCst);
        shutdown_control_stream(&self.control_stream);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct ShutdownControlOnExit(Arc<Mutex<Option<TcpStream>>>);

impl Drop for ShutdownControlOnExit {
    fn drop(&mut self) {
        shutdown_control_stream(&self.0);
    }
}

fn shutdown_control_stream(control_stream: &Arc<Mutex<Option<TcpStream>>>) {
    let control = control_stream
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(stream) = control.as_ref() {
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn serve(
    listener: TcpListener,
    mode: Mode,
    reply: Status,
    cancelled: Arc<AtomicBool>,
    shared_control: Arc<Mutex<Option<TcpStream>>>,
) -> Result<(), String> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let (mut control, _) = accept_until(&listener, deadline, &cancelled)?;
    control
        .set_read_timeout(Some(POLL_INTERVAL))
        .map_err(|error| format!("set control read timeout: {error}"))?;
    control
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|error| format!("set control write timeout: {error}"))?;
    *shared_control
        .lock()
        .map_err(|_| "lock scripted FTP control stream".to_owned())? =
        Some(control.try_clone().map_err(|error| error.to_string())?);
    write_reply(&mut control, Status::Ready, "scripted server ready")?;

    let (data_listener, active_address) = match mode {
        Mode::Passive => {
            expect_command(&mut control, &cancelled, "PASV")?;
            let data_listener = TcpListener::bind(("127.0.0.1", 0))
                .map_err(|error| format!("bind passive data listener: {error}"))?;
            data_listener
                .set_nonblocking(true)
                .map_err(|error| format!("make passive listener nonblocking: {error}"))?;
            let address = data_listener
                .local_addr()
                .map_err(|error| format!("read passive listener address: {error}"))?;
            let octets = match address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => return Err("expected IPv4 passive listener".into()),
            };
            write_reply(
                &mut control,
                Status::PassiveMode,
                &format!(
                    "Entering Passive Mode ({},{},{},{},{},{})",
                    octets[0],
                    octets[1],
                    octets[2],
                    octets[3],
                    address.port() / 256,
                    address.port() % 256
                ),
            )?;
            (Some(data_listener), None)
        }
        Mode::ExtendedPassive => {
            expect_command(&mut control, &cancelled, "EPSV")?;
            let data_listener = TcpListener::bind(("127.0.0.1", 0))
                .map_err(|error| format!("bind extended passive data listener: {error}"))?;
            data_listener
                .set_nonblocking(true)
                .map_err(|error| format!("make extended passive listener nonblocking: {error}"))?;
            let address = data_listener
                .local_addr()
                .map_err(|error| format!("read extended passive listener address: {error}"))?;
            write_reply(
                &mut control,
                Status::ExtendedPassiveMode,
                &format!("Entering Extended Passive Mode (|||{}|)", address.port()),
            )?;
            (Some(data_listener), None)
        }
        Mode::Active => (None, Some(expect_active_setup(&mut control, &cancelled)?)),
    };

    let data_stream = if let Some(data_listener) = data_listener {
        let data_stream = accept_until(&data_listener, Instant::now() + IO_TIMEOUT, &cancelled)?.0;
        data_stream
            .set_read_timeout(Some(POLL_INTERVAL))
            .map_err(|error| format!("set passive data read timeout: {error}"))?;
        data_stream
    } else {
        // Active mode receives the PORT address from the setup command.
        let command = read_command(&mut control, &cancelled)?;
        if command != "RETR probe" {
            return Err(format!("expected RETR probe, received {command:?}"));
        }
        write_reply(&mut control, reply, "scripted transfer response")?;
        if is_preliminary(reply) {
            let active_address = active_address.expect("active mode address must be configured");
            let stream = TcpStream::connect_timeout(&active_address, IO_TIMEOUT)
                .map_err(|error| format!("connect active data socket: {error}"))?;
            drop(stream);
        }
        expect_noop(&mut control, &cancelled)?;
        return Ok(());
    };

    let command = read_command(&mut control, &cancelled)?;
    if command != "RETR probe" {
        return Err(format!("expected RETR probe, received {command:?}"));
    }
    write_reply(&mut control, reply, "scripted transfer response")?;
    drop(data_stream);
    expect_noop(&mut control, &cancelled)
}

fn expect_active_setup(
    control: &mut TcpStream,
    cancelled: &AtomicBool,
) -> Result<SocketAddr, String> {
    let command = read_command(control, cancelled)?;
    let address = if let Some(arguments) = command.strip_prefix("PORT ") {
        let values = arguments
            .split(',')
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("parse PORT command: {error}"))?;
        if values.len() != 6 || values[..4].iter().any(|value| *value > 255) {
            return Err(format!("invalid PORT command {command:?}"));
        }
        let address = SocketAddr::from((
            [
                values[0] as u8,
                values[1] as u8,
                values[2] as u8,
                values[3] as u8,
            ],
            values[4] * 256 + values[5],
        ));
        address
    } else if let Some(arguments) = command.strip_prefix("EPRT ") {
        let fields = arguments.split('|').collect::<Vec<_>>();
        if fields.len() < 5 {
            return Err(format!("invalid EPRT command {command:?}"));
        }
        let ip = fields[2]
            .parse()
            .map_err(|error| format!("parse EPRT address: {error}"))?;
        let port = fields[3]
            .parse()
            .map_err(|error| format!("parse EPRT port: {error}"))?;
        SocketAddr::new(ip, port)
    } else {
        return Err(format!("expected PORT or EPRT, received {command:?}"));
    };
    write_reply(control, Status::CommandOk, "active mode configured")?;
    Ok(address)
}

fn expect_command(
    control: &mut TcpStream,
    cancelled: &AtomicBool,
    expected: &str,
) -> Result<(), String> {
    let command = read_command(control, cancelled)?;
    if command == expected {
        Ok(())
    } else {
        Err(format!("expected {expected}, received {command:?}"))
    }
}

fn expect_noop(control: &mut TcpStream, cancelled: &AtomicBool) -> Result<(), String> {
    let command = read_command(control, cancelled)?;
    if command != "NOOP" {
        return Err(format!("expected NOOP, received {command:?}"));
    }
    write_reply(control, Status::CommandOk, "NOOP okay")
}

fn read_command(control: &mut TcpStream, cancelled: &AtomicBool) -> Result<String, String> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut bytes = Vec::new();
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err("server cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("timed out reading FTP command".into());
        }
        let mut byte = [0; 1];
        match control.read(&mut byte) {
            Ok(0) => return Err("control connection closed".into()),
            Ok(_) if byte[0] == b'\n' => {
                if bytes.last() == Some(&b'\r') {
                    bytes.pop();
                }
                return String::from_utf8(bytes).map_err(|error| error.to_string());
            }
            Ok(_) => bytes.push(byte[0]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("read FTP command: {error}")),
        }
    }
}

fn write_reply(control: &mut TcpStream, status: Status, body: &str) -> Result<(), String> {
    write!(control, "{} {body}\r\n", status.code())
        .map_err(|error| format!("write FTP reply: {error}"))
}

fn accept_until(
    listener: &TcpListener,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<(TcpStream, SocketAddr), String> {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return Err("server cancelled".into());
        }
        if Instant::now() >= deadline {
            return Err("timed out accepting FTP socket".into());
        }
        match listener.accept() {
            Ok(connection) => return Ok(connection),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::yield_now();
            }
            Err(error) => return Err(format!("accept FTP socket: {error}")),
        }
    }
}

fn is_preliminary(status: Status) -> bool {
    matches!(status, Status::AlreadyOpen | Status::AboutToSend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_close_control_connection_when_passive_accept_times_out() {
        let server = ScriptedDataServer::start(Mode::Passive, Status::FileUnavailable);
        let mut stream = TcpStream::connect(server.address()).unwrap();
        let read_timeout = IO_TIMEOUT + IO_TIMEOUT;
        stream.set_read_timeout(Some(read_timeout)).unwrap();
        stream.set_write_timeout(Some(read_timeout)).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        let mut reply = String::new();
        reader.read_line(&mut reply).unwrap();
        assert!(reply.starts_with("220 "));

        stream.write_all(b"PASV\r\n").unwrap();
        reply.clear();
        reader.read_line(&mut reply).unwrap();
        assert!(reply.starts_with("227 "));

        // Model the old ordering: send RETR, but wait for its reply without
        // opening the passive data connection the server is currently accepting.
        stream.write_all(b"RETR probe\r\n").unwrap();
        reply.clear();
        let started = Instant::now();
        let read = reader.read_line(&mut reply);

        assert_eq!(
            read.unwrap(),
            0,
            "server should close the failed control socket"
        );
        assert!(
            started.elapsed() < read_timeout,
            "control read should finish before its timeout"
        );

        drop(reader);
        drop(stream);
        drop(server);
    }
}
