use criterion::{black_box, criterion_group, criterion_main, Criterion};
use nxp_key_diversifier_2tdea_av2::{diversify_2tdea_versionrestore_av2, generate_subkeys_des, SubKeys};

fn criterion_benchmark(c: &mut Criterion) {
    let s_key = &[0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let version = Some(0x55_u8);
    let s_div = &[0x04_u8, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41];

    let result = &mut [0_u8; 16];

    let sk = generate_subkeys_des(s_key); // Initializes Encoders and generates keys

    c.bench_function("diversify_key_2tdea_cbc_av2", |b| b.iter(|| diversify_2tdea_versionrestore_av2(black_box(&sk), black_box(s_div.to_vec()), &version,result)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);