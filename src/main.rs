extern crate netlink_rs;
extern crate bincode;
extern crate rustc_serialize;
#[macro_use]
extern crate clap;

use std::io::{self, ErrorKind, Cursor};
use clap::{Arg, App, ArgMatches, AppSettings};
use rustc_serialize::json::{as_pretty_json};
use netlink_rs::socket::{Socket, Payload, Msg, NlMsgHeader, NetlinkAddr};
use netlink_rs::Protocol;
use std::process;
use std::str;
use std::net::Ipv4Addr;

pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 3;
pub const IPPROTO_TCP: u8 = 6;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const TCPF_ALL: u32 = 0xFFF;
pub const NETLINK_INET_DIAG: i32 = 4;

pub struct SockAddrIn {
    family: u8,
    port: u8,
    addr: InAddr
}

pub struct InAddr {
    s_addr: u32
}

#[derive(RustcEncodable)]
#[derive(Debug)]
pub struct TcpCon {
    pub tcp_established: i64,
    pub tcp_syn_sent: i64,
    pub tcp_syn_recv: i64,
    pub tcp_fin_wait1: i64,
    pub tcp_fin_wait2: i64,
    pub tcp_time_wait: i64,
    pub tcp_close: i64,
    pub tcp_close_wait: i64,
    pub tcp_last_ack: i64,
    pub tcp_listen: i64,
    pub tcp_closing: i64,
    pub tcp_max_states: i64
}

impl ::std::default::Default for TcpCon {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}


#[derive(RustcEncodable, RustcDecodable)]
#[derive(Debug)]
#[repr(C)]
pub struct NLMsgHeader {
    msg_length: u32,
    nl_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}


#[derive(RustcEncodable, RustcDecodable)]
#[derive(Debug)]
#[repr(C)]
pub struct InetDiagSocketID {
    pub sport: u16,
    pub dport: u16,
    pub src: (u32, u32, u32, u32),
    pub dst: (u32, u32, u32, u32),
    pub if_: u32,
    pub cookie: (u32, u32),
}

impl ::std::default::Default for InetDiagSocketID {
    fn default() -> Self {
        InetDiagSocketID {
            sport: 0,
            dport: 0,
            src: (0, 0, 0, 0),
            dst: (0, 0, 0, 0),
            if_: 0,
            cookie: (0, 0)
        }
    }
}

#[derive(RustcEncodable, RustcDecodable)]
#[derive(Debug)]
#[repr(C)]
pub struct InetDiagV2 {
    pub family: u8,
    pub protocol: u8,
    pub states: u32,
    pub id: InetDiagSocketID,
    pub ext: u8,
    pub _pad: u8,
}

impl ::std::default::Default for InetDiagV2 {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

#[derive(RustcEncodable, RustcDecodable)]
#[derive(Debug)]
#[repr(C)]
pub struct InetDiagMsg {
    pub family: u8,
    pub state: u8,
    pub timer: u8,
    pub retrans: u8,
    pub id: InetDiagSocketID,
    pub expires: u32,
    pub rqueue: u32,
    pub wqueue: u32,
    pub uid: u32,
    pub iode: u32
}

impl ::std::default::Default for InetDiagMsg {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

fn parsing(vec: Vec<Msg>, contkr: &mut TcpCon, matches: &ArgMatches) {
    for reply in vec {
        if reply.bytes().unwrap().len() == 96 {
            let bytes: &[u8] = &reply.bytes().unwrap();
            let data = &bytes[16..96];
            let msg: InetDiagMsg = bincode::rustc_serialize::decode(data).unwrap();
            if matches.is_present("connections") {
                if msg.state != 10 {
                    println!("{}:{} -> {}:{}", Ipv4Addr::from(msg.id.src.0), msg.id.sport, Ipv4Addr::from(msg.id.dst.0), msg.id.dport);
                }
            }
            if matches.is_present("states") {
                match msg.state {
                    1 => contkr.tcp_established += 1,
                    2 => contkr.tcp_syn_sent += 1,
                    3 => contkr.tcp_syn_recv += 1,
                    4 => contkr.tcp_fin_wait1 += 1,
                    5 => contkr.tcp_fin_wait2 += 1,
                    6 => contkr.tcp_time_wait += 1,
                    7 => contkr.tcp_close += 1,
                    8 => contkr.tcp_close_wait += 1,
                    9 => contkr.tcp_last_ack += 1,
                    10 => contkr.tcp_listen += 1,
                    11 => contkr.tcp_closing += 1,
                    12 => contkr.tcp_max_states += 1,
                    _ => println!("here be daemons...")
                }
            }
        }
    }
    if matches.is_present("states") {
        println!("{}", as_pretty_json(contkr))
    }
}

fn main() {
    let matches = App::new(crate_name!()).setting(AppSettings::ArgRequiredElseHelp)
        .version(crate_version!())
        .author("Willaim Fleming <wfleming@grumpysysadm.com>")
        .about("parsing tool for tcp net")
        .arg(Arg::with_name("version")
            .short("V")
            .long("version")
            .help("print version info"))
        .arg(Arg::with_name("connections")
            .short("c")
            .long("connections")
            .multiple(true)
            .help("prints connections"))
        .arg(Arg::with_name("states")
            .short("s")
            .long("states")
            .multiple(true)
            .help("prints summary in json")).get_matches();
    if matches.is_present("version") {
        println!("rnstat version {}", crate_version!())
    }
    let mut nl_sock = Socket::new(Protocol::INETDiag).unwrap();
    let nl_sock_addr = NetlinkAddr::new(0, 0);
    let payload = InetDiagV2 { family: AF_INET, protocol: IPPROTO_TCP, states: TCPF_ALL, id: InetDiagSocketID { ..Default::default() }, ..Default::default() };
    let gen_bytes = bincode::rustc_serialize::encode(&payload, bincode::SizeLimit::Bounded(56)).unwrap();
    let mut shdr = NlMsgHeader::user_defined(20, 56);
    shdr.data_length(56).seq(178431).pid(0).dump();
    let msg = Msg::new(shdr, Payload::Data(&gen_bytes));
    let mut contkr = TcpCon { ..Default::default() };
    nl_sock.send(msg, &nl_sock_addr);
    loop {
        let (addr, vec) = nl_sock.recv().unwrap();
        if vec.len() != 0 {
            parsing(vec, &mut contkr, &matches);
        } else {
            break
        }
    }
}
