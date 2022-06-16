// © 2022 Anssi Eteläniemi <aetelani@hotmail.com>
#![feature(test)]
#![feature(once_cell)]

extern crate test;

use std::lazy::SyncOnceCell;
use bitvec::macros::internal::funty::Fundamental;
use bitvec::prelude::*;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use des::cipher::{Block, BlockEncrypt, KeyInit};
use des::cipher::block_padding::ZeroPadding;
use des::TdesEde2;

pub type SubKey = Vec<u8>;

#[derive(Debug)]
pub struct SubKeys(SubKey,
               SubKey,
               SubKey);

type Tdes2EdeCbcEnc = cbc::Encryptor<TdesEde2>;
static mut ENCTDES2EDECBC: SyncOnceCell<Tdes2EdeCbcEnc> = SyncOnceCell::new();
static mut ENCTDES2EDE: SyncOnceCell<TdesEde2> = SyncOnceCell::new();

fn bitshift_des(key: &[u8]) -> SubKey {
    let key_first = key.first().unwrap();
    let is_last_bit_true = *key_first.view_bits::<Lsb0>().last().unwrap();
    let mut pokey = key.iter().peekable();
    let mut result = vec!();
    while let Some(v) = pokey.next() {
        let mut b0 = v.clone();
        let b0_shr_lsb = b0.view_bits_mut::<Lsb0>();
        b0_shr_lsb.shift_right(1);
        if let Some(b) = pokey.peek() {
            let mut b1 = *b.clone();
            let b1_bv = b1.view_bits_mut::<Lsb0>().last().unwrap().as_u8();
            let r = b0_shr_lsb.load::<u8>() | b1_bv;
            result.push(r);
        } else {
            let rs = if is_last_bit_true {
                0b00011011
            } else {
                0x00_u8
            };

            let value = b0_shr_lsb.load::<u8>() ^ rs;
            result.push(value as u8);
        }
    }
    result
}

fn encrypt_des_cbc(input: [u8; 16]) -> Vec<u8> {
    let c0 = unsafe { ENCTDES2EDECBC.get().expect("Key(s) not initialized with generate_subkeys_des") };
    let mut inp0 = input.clone();
    let result = c0.clone().encrypt_padded_mut::<ZeroPadding>(inp0.as_mut_slice(), 16);
    result.unwrap().to_vec()
}

pub fn generate_subkeys_des(key: &[u8]) -> SubKeys {
    unsafe {
        let _ = ENCTDES2EDECBC.take();
        let _ = ENCTDES2EDE.take();
    };
    let _ = unsafe { ENCTDES2EDECBC.set(Tdes2EdeCbcEnc::new_from_slices(key, &[0_u8; 8]).unwrap()) };
    let c = unsafe { ENCTDES2EDE.get_or_init(|| des::TdesEde2::new_from_slice(key).unwrap()) };
    let input0 = &mut Block::<TdesEde2>::from([0_u8; 8]);
    c.encrypt_block(input0.into());
    let input1 = bitshift_des(input0.as_slice());
    let input2= bitshift_des(input1.as_slice());

    SubKeys(input0.to_vec(), input1, input2)
}

pub fn diversify_2tdea_versionrestore_av2(subkeys: &SubKeys, divinput: Vec<u8>, version: &Option<u8>, key_result: &mut [u8; 16]) {
    let mut result = [8_u8; 16];

    let inputd1 = prepare_input_des(&subkeys, &divinput, &0x21);
    let derived1 = encrypt_des_cbc(inputd1);
    let inputd2 = prepare_input_des(&subkeys, &divinput, &0x22);
    let derived2 = encrypt_des_cbc(inputd2);

    result[..8].copy_from_slice(&derived1[8..]);
    result[8..].copy_from_slice(&derived2[8..]);



    if let Some(version_exists) = version {
        let res = restore_version_des_av2(&result, version_exists);
        key_result.copy_from_slice(&res);
    } else {
        key_result.copy_from_slice(&result);
    }
}

fn restore_version_des_av2(divoutput: &[u8; 16], version: &u8) -> [u8; 16] {
    let mut v_bits = version.view_bits::<Msb0>().iter().cycle();
    let mut result = [0_u8; 16];
    for (i, v) in divoutput.clone().iter_mut().enumerate() {
        let vb = v_bits.next().unwrap();
        let mut v0 = v.load_value();
        v0.view_bits_mut::<Lsb0>().set(0, vb.as_u8().as_bool());
        result[i] = v0;
    }
    result
}

fn prepare_input_des(subkeys: &SubKeys, divinput: &Vec<u8>, divconst: &u8) -> [u8; 16] {
    const DIVERSIFIER_MAX_LEN: usize = 15; // if longer then panic TODO: Result
    let mut result = [0_u8; 16];
    let subkey;

    let divinput_offset = divinput.len() + 1; // divinput.len + divconst.len
    result[0] = *divconst;
    result[1..divinput_offset].copy_from_slice(divinput);

    let padding_len = DIVERSIFIER_MAX_LEN.checked_sub(divinput.len()).expect("Diversifier too long");
    let mut padding = vec![0_u8; padding_len];
    if let Some(p) = padding.first_mut() {
        *p = 0x80_u8;
        result[divinput_offset..].copy_from_slice(&padding);
        subkey = &subkeys.2;
    } else {
        subkey = &subkeys.1;
    }

    result.iter_mut().skip(8).zip(subkey).for_each(|(x1, x2)| *x1 ^= *x2);

    result
}

#[cfg(test)]
mod tests {
    use crate::{diversify_2tdea_versionrestore_av2, generate_subkeys_des};
    use test::Bencher;

    #[test]
    fn test_2tdea_av2_public_example() {
        let s_key = &[0x0F_u8, 0x2F, 0x7F, 0x4A, 0x5A, 0x3F, 0x7F, 0x8F, 0x9E, 0xAE, 0xAE, 0xAE, 0xAE, 0xEE, 0xAE, 0x0E];
        let version = Some(240_u8);

        let s_div = &[0x82, 0x04, 0x6E, 0x33, 0x42, 0xC9, 0x4C, 0x82];
        let target = [93_u8, 155, 245, 5, 2, 174, 236, 6, 155, 83, 39, 21, 220, 252, 22, 22];
        let result = &mut [0_u8; 16];

        let sk = generate_subkeys_des(s_key);
        diversify_2tdea_versionrestore_av2(&sk, s_div.to_vec(), &version,result);
        assert_eq!(result.to_vec(), target.to_vec());
    }

    #[test]
    fn test_2tdea_av2_public_example_an10922() {
        let s_key = &[0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let version = Some(0x55_u8);
        let s_div = &[0x04_u8, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41];
        let target = [0x16_u8, 0xf9, 0x58, 0x7d, 0x9e, 0x89, 0x10, 0xc9, 0x6a, 0x97, 0x48, 0xd1, 0x06, 0x11, 0x7c, 0xd7];

        let result = &mut [0_u8; 16];

        let sk = generate_subkeys_des(s_key);
        diversify_2tdea_versionrestore_av2( &sk, s_div.to_vec(), &version, result);
        assert_eq!(result.to_vec(), target.to_vec());
    }

    #[bench]
    fn bench_diversify_2tdea_versionrestore_av2(b: &mut Bencher) {
        let s_key = &[0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let version = Some(0x55_u8);
        let s_div = &[0x04_u8, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41];

        let result = &mut [0_u8; 16];

        let sk = generate_subkeys_des(s_key); // Initializes Encoders and generates keys
        b.iter(|| diversify_2tdea_versionrestore_av2(&sk,s_div.to_vec(), &version,result));
    }
}
