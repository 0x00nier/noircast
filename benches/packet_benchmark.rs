//! Benchmarks for packet building and sending
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::net::{IpAddr, Ipv4Addr};

// Import from the correct crate name
use noircast::network::protocols::{
    DnsQuery, DnsType, NtpPacket, SnmpGetRequest, SsdpRequest,
    SmbNegotiatePacket, LdapSearchRequest, NetBiosNsPacket,
    DhcpDiscoverPacket, KerberosAsReq, ArpPacket,
};
use noircast::network::batch_sender::{BufferPool, PacketBuffer};
use noircast::network::sender::PacketSender;

// ============================================================================
// Buffer Pool Benchmarks
// ============================================================================

fn benchmark_buffer_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool");

    for pool_size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(pool_size),
            pool_size,
            |b, &size| {
                let pool = BufferPool::new(size, 4096);
                b.iter(|| {
                    let buf = pool.acquire();
                    black_box(&buf);
                    pool.release(buf);
                })
            },
        );
    }

    group.finish();
}

fn benchmark_packet_buffer(c: &mut Criterion) {
    c.bench_function("packet_buffer_new", |b| {
        b.iter(|| {
            let buf = PacketBuffer::new(4096);
            black_box(buf)
        })
    });

    c.bench_function("packet_buffer_write", |b| {
        let mut buf = PacketBuffer::new(4096);
        let data = vec![0u8; 1000];
        b.iter(|| {
            buf.buffer()[..data.len()].copy_from_slice(&data);
            buf.set_len(data.len());
            black_box(buf.as_slice().len())
        })
    });
}

// ============================================================================
// DNS Protocol Benchmarks
// ============================================================================

fn benchmark_dns_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_packet");
    group.throughput(Throughput::Elements(1));

    group.bench_function("build_dns_a_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new().add_question("example.com", DnsType::A);
            black_box(query.build())
        })
    });

    group.bench_function("build_dns_aaaa_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new().add_question("example.com", DnsType::Aaaa);
            black_box(query.build())
        })
    });

    group.bench_function("build_dns_mx_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new().add_question("example.com", DnsType::Mx);
            black_box(query.build())
        })
    });

    group.bench_function("build_dns_txt_query", |b| {
        b.iter(|| {
            let query = DnsQuery::new().add_question("example.com", DnsType::Txt);
            black_box(query.build())
        })
    });

    group.bench_function("a_query_shorthand", |b| {
        b.iter(|| {
            let query = DnsQuery::a_query("example.com");
            black_box(query.build())
        })
    });

    group.finish();
}

// ============================================================================
// NTP Protocol Benchmarks
// ============================================================================

fn benchmark_ntp_packet_building(c: &mut Criterion) {
    c.bench_function("build_ntp_packet", |b| {
        b.iter(|| {
            let ntp = NtpPacket::new();
            black_box(ntp.build())
        })
    });
}

// ============================================================================
// SNMP Protocol Benchmarks
// ============================================================================

fn benchmark_snmp_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("snmp_packet");

    group.bench_function("build_snmp_get_single_oid", |b| {
        b.iter(|| {
            let snmp = SnmpGetRequest::new("public").add_oid("1.3.6.1.2.1.1.1.0");
            black_box(snmp.build())
        })
    });

    group.bench_function("build_snmp_get_multiple_oids", |b| {
        b.iter(|| {
            let snmp = SnmpGetRequest::new("public")
                .add_oid("1.3.6.1.2.1.1.1.0")
                .add_oid("1.3.6.1.2.1.1.3.0")
                .add_oid("1.3.6.1.2.1.1.5.0");
            black_box(snmp.build())
        })
    });

    group.finish();
}

// ============================================================================
// SSDP Protocol Benchmarks
// ============================================================================

fn benchmark_ssdp_packet_building(c: &mut Criterion) {
    c.bench_function("build_ssdp_m_search", |b| {
        b.iter(|| {
            let ssdp = SsdpRequest::m_search();
            black_box(ssdp.build())
        })
    });
}

// ============================================================================
// SMB Protocol Benchmarks
// ============================================================================

fn benchmark_smb_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("smb_packet");

    group.bench_function("build_smb_negotiate_default", |b| {
        b.iter(|| {
            let smb = SmbNegotiatePacket::new();
            black_box(smb.build())
        })
    });

    group.bench_function("build_smb_negotiate_smb1_only", |b| {
        b.iter(|| {
            let smb = SmbNegotiatePacket::smb1_only();
            black_box(smb.build())
        })
    });

    group.bench_function("build_smb_negotiate_smb2_only", |b| {
        b.iter(|| {
            let smb = SmbNegotiatePacket::smb2_only();
            black_box(smb.build())
        })
    });

    group.finish();
}

// ============================================================================
// LDAP Protocol Benchmarks
// ============================================================================

fn benchmark_ldap_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("ldap_packet");

    group.bench_function("build_ldap_rootdse_query", |b| {
        b.iter(|| {
            let ldap = LdapSearchRequest::rootdse_query();
            black_box(ldap.build())
        })
    });

    group.bench_function("build_ldap_custom_search", |b| {
        b.iter(|| {
            use noircast::network::protocols::LdapScope;
            let ldap = LdapSearchRequest::new("dc=example,dc=com")
                .scope(LdapScope::WholeSubtree)
                .filter("(objectClass=*)");
            black_box(ldap.build())
        })
    });

    group.finish();
}

// ============================================================================
// NetBIOS Protocol Benchmarks
// ============================================================================

fn benchmark_netbios_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("netbios_packet");

    group.bench_function("build_netbios_name_query", |b| {
        b.iter(|| {
            let nb = NetBiosNsPacket::name_query("WORKGROUP");
            black_box(nb.build())
        })
    });

    group.bench_function("build_netbios_node_status", |b| {
        b.iter(|| {
            let nb = NetBiosNsPacket::node_status_query("*");
            black_box(nb.build())
        })
    });

    group.finish();
}

// ============================================================================
// DHCP Protocol Benchmarks
// ============================================================================

fn benchmark_dhcp_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("dhcp_packet");

    group.bench_function("build_dhcp_discover", |b| {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        b.iter(|| {
            let dhcp = DhcpDiscoverPacket::new(mac);
            black_box(dhcp.build())
        })
    });

    group.bench_function("build_dhcp_discover_with_hostname", |b| {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        b.iter(|| {
            let dhcp = DhcpDiscoverPacket::new(mac).with_hostname("testhost");
            black_box(dhcp.build())
        })
    });

    group.finish();
}

// ============================================================================
// Kerberos Protocol Benchmarks
// ============================================================================

fn benchmark_kerberos_packet_building(c: &mut Criterion) {
    c.bench_function("build_kerberos_as_req", |b| {
        b.iter(|| {
            let krb = KerberosAsReq::new("EXAMPLE.COM", "testuser");
            black_box(krb.build())
        })
    });
}

// ============================================================================
// ARP Protocol Benchmarks
// ============================================================================

fn benchmark_arp_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("arp_packet");

    group.bench_function("build_arp_request", |b| {
        let sender_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_ip = [192, 168, 1, 100];
        let target_ip = [192, 168, 1, 1];
        b.iter(|| {
            let arp = ArpPacket::new_request(sender_mac, sender_ip, target_ip);
            black_box(arp.build())
        })
    });

    group.bench_function("build_arp_reply", |b| {
        let sender_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_ip = [192, 168, 1, 100];
        let target_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let target_ip = [192, 168, 1, 1];
        b.iter(|| {
            let arp = ArpPacket::new_reply(sender_mac, sender_ip, target_mac, target_ip);
            black_box(arp.build())
        })
    });

    group.finish();
}

// ============================================================================
// UDP Probe Benchmarks
// ============================================================================

fn benchmark_udp_probe_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_probes");

    for port in [53u16, 123, 161, 1900, 137, 5060, 69, 80].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(port),
            port,
            |b, &port| {
                b.iter(|| {
                    let probe = PacketSender::get_udp_probe(port);
                    black_box(probe.len())
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Batch Processing Benchmarks
// ============================================================================

fn benchmark_batch_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing");
    group.sample_size(50);

    for size in [100, 500, 1000, 5000].iter() {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                // Use iterator collect for faster batch creation
                let batch: Vec<u16> = (1..=size as u16).collect();
                black_box(batch.len())
            })
        });
    }

    group.finish();
}

// ============================================================================
// Checksum Benchmarks
// ============================================================================

fn benchmark_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    group.bench_function("icmp_checksum_64bytes", |b| {
        let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
        b.iter(|| {
            let checksum = calculate_checksum(&data);
            black_box(checksum)
        })
    });

    group.bench_function("icmp_checksum_1024bytes", |b| {
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        b.iter(|| {
            let checksum = calculate_checksum(&data);
            black_box(checksum)
        })
    });

    group.bench_function("icmp_checksum_4096bytes", |b| {
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        b.iter(|| {
            let checksum = calculate_checksum(&data);
            black_box(checksum)
        })
    });

    group.finish();
}

/// Calculate Internet checksum (used in ICMP, TCP, UDP)
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

// ============================================================================
// IP Parsing Benchmarks
// ============================================================================

fn benchmark_ip_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ip_parsing");

    group.bench_function("parse_ipv4_string", |b| {
        let ip_str = "192.168.1.100";
        b.iter(|| {
            let ip: IpAddr = ip_str.parse().unwrap();
            black_box(ip)
        })
    });

    group.bench_function("create_ipv4_direct", |b| {
        b.iter(|| {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
            black_box(ip)
        })
    });

    group.bench_function("parse_ipv6_string", |b| {
        let ip_str = "2001:db8::1";
        b.iter(|| {
            let ip: IpAddr = ip_str.parse().unwrap();
            black_box(ip)
        })
    });

    group.finish();
}

// ============================================================================
// All Protocols Combined Benchmark
// ============================================================================

fn benchmark_all_protocols(c: &mut Criterion) {
    let mut group = c.benchmark_group("all_protocols");
    group.throughput(Throughput::Elements(1));

    group.bench_function("dns", |b| {
        b.iter(|| black_box(DnsQuery::a_query("example.com").build()))
    });

    group.bench_function("ntp", |b| {
        b.iter(|| black_box(NtpPacket::new().build()))
    });

    group.bench_function("snmp", |b| {
        b.iter(|| black_box(SnmpGetRequest::new("public").add_oid("1.3.6.1.2.1.1.1.0").build()))
    });

    group.bench_function("ssdp", |b| {
        b.iter(|| black_box(SsdpRequest::m_search().build()))
    });

    group.bench_function("smb", |b| {
        b.iter(|| black_box(SmbNegotiatePacket::new().build()))
    });

    group.bench_function("ldap", |b| {
        b.iter(|| black_box(LdapSearchRequest::rootdse_query().build()))
    });

    group.bench_function("netbios", |b| {
        b.iter(|| black_box(NetBiosNsPacket::node_status_query("*").build()))
    });

    group.bench_function("dhcp", |b| {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        b.iter(|| black_box(DhcpDiscoverPacket::new(mac).build()))
    });

    group.bench_function("kerberos", |b| {
        b.iter(|| black_box(KerberosAsReq::new("EXAMPLE.COM", "user").build()))
    });

    group.bench_function("arp", |b| {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sender_ip = [192, 168, 1, 100];
        let target_ip = [192, 168, 1, 1];
        b.iter(|| black_box(ArpPacket::new_request(mac, sender_ip, target_ip).build()))
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    buffer_benches,
    benchmark_buffer_pool,
    benchmark_packet_buffer,
);

criterion_group!(
    protocol_benches,
    benchmark_dns_packet_building,
    benchmark_ntp_packet_building,
    benchmark_snmp_packet_building,
    benchmark_ssdp_packet_building,
    benchmark_smb_packet_building,
    benchmark_ldap_packet_building,
    benchmark_netbios_packet_building,
    benchmark_dhcp_packet_building,
    benchmark_kerberos_packet_building,
    benchmark_arp_packet_building,
    benchmark_all_protocols,
);

criterion_group!(
    network_benches,
    benchmark_udp_probe_generation,
    benchmark_batch_sizes,
    benchmark_checksum,
    benchmark_ip_parsing,
);

criterion_main!(buffer_benches, protocol_benches, network_benches);
