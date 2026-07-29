use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub fn bind_pmtud_probe_socket() -> Result<Arc<UdpSocket>> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("pmtud probe socket create")?;
    s.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())
        .context("pmtud probe bind")?;
    set_socket_dont_fragment(&s).context("pmtud dont-fragment / mtu-discover")?;
    let std_sock: std::net::UdpSocket = s.into();
    std_sock
        .set_nonblocking(true)
        .context("pmtud probe nonblocking")?;
    Ok(Arc::new(
        UdpSocket::from_std(std_sock).context("pmtud probe tokio wrap")?,
    ))
}

fn set_socket_dont_fragment(s: &Socket) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows::Win32::Networking::WinSock::{
            setsockopt, WSAGetLastError, IPPROTO_IP, SOCKET,
        };
        const IP_DONTFRAGMENT: i32 = 14;
        let opt = 1u32.to_ne_bytes();
        let ret = unsafe {
            setsockopt(
                SOCKET(s.as_raw_socket() as usize),
                IPPROTO_IP.0 as i32,
                IP_DONTFRAGMENT,
                Some(&opt),
            )
        };
        if ret != 0 {
            let err = unsafe { WSAGetLastError().0 as i32 };
            return Err(std::io::Error::from_raw_os_error(err));
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let enable: libc::c_int = libc::IP_PMTUDISC_DO;
        let r = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = s;
        Ok(())
    }
}
