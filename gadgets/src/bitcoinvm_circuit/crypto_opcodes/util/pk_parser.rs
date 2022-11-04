use std::vec;

use halo2_proofs::halo2curves::{secp256k1::{self, Secp256k1Affine}, CurveAffine};
use crate::bitcoinvm_circuit::{constants::*, crypto_opcodes::checksig::checksig_util::{pk_bytes_swap_endianness, ct_option_ok_or}};
use libsecp256k1::PublicKey;

#[derive(Clone, Debug)]
pub(crate) struct PublicKeyInScript {
    pub bytes: Vec<u8>,
    pub pk: Secp256k1Affine, 
}

#[derive(Debug, Clone)]
pub enum StackElement {
    InvalidSignature,
    ValidSignature,
    Data(Vec<u8>),
}

pub(crate) fn collect_public_keys(
    script: Vec<u8>,
    initial_stack: Vec<StackElement>,
) -> Result<Vec<PublicKeyInScript>, libsecp256k1::Error>  {
    use StackElement::Data as Data;
    let mut collected_keys: Vec<PublicKeyInScript> = vec![];
    let mut stack: Vec<StackElement> = initial_stack;
    let mut script_byte_index: usize = 0;
    let mut opcode: usize;
    
    while script_byte_index < script.len() {
        opcode = script[script_byte_index] as usize;

        if opcode == OP_0 {
            stack.insert(0, Data(vec![]));
            script_byte_index += 1;
        }
        else if opcode >= OP_1 && opcode <= OP_16 {
            stack.insert(0, Data(vec![(opcode - OP_RESERVED) as u8]));
            script_byte_index += 1;
        }
        else if opcode >= OP_PUSH_NEXT1 && opcode <= OP_PUSH_NEXT75 {
            let data = script[script_byte_index+1..(script_byte_index+opcode+1)].to_vec();
            stack.insert(0, Data(data));
            script_byte_index += opcode + 1;
        }
        else if opcode == OP_PUSHDATA1 {
            let data_length: usize = script[script_byte_index+1] as usize;
            let data = script[script_byte_index+2..(script_byte_index+data_length+2)].to_vec();
            stack.insert(0, Data(data));
            script_byte_index += data_length + 2;
        }
        else if opcode == OP_PUSHDATA2 {
            let data_length: usize = (script[script_byte_index+1] as usize) + 256usize * (script[script_byte_index+2] as usize);
            let data = script[script_byte_index+3..(script_byte_index+data_length+3)].to_vec();
            stack.insert(0, Data(data));
            script_byte_index += data_length + 3;
        }
        else if opcode == OP_PUSHDATA4 {
            let data_length: usize = (script[script_byte_index+1] as usize) 
                + (1 << 8) * (script[script_byte_index+2] as usize)
                + (1 << 16) * (script[script_byte_index+3] as usize)
                + (1 << 24) * (script[script_byte_index+4] as usize);

            let data = script[script_byte_index+5..(script_byte_index+data_length+5)].to_vec();
            stack.insert(0, Data(data));
            script_byte_index += data_length + 5;
        }
        else if opcode == OP_CHECKSIG {
            match stack[1] {
                StackElement::InvalidSignature => {
                    stack.remove(0); // Remove the public key
                    stack.remove(0); // Remove stack item corresponding to the invalid signature
                    script_byte_index += 1;
                },
                StackElement::ValidSignature => {
                    let stack_top = stack.remove(0); // Remove the public key
                    match stack_top {
                        Data(pk_bytes) => {
                            let prefix = pk_bytes[0] as u64;
                            let parsed_pk = if prefix == PREFIX_PK_UNCOMPRESSED {
                                // The below step implicitly checks that the pk is on the curve
                                PublicKey::parse(pk_bytes.as_slice().try_into().expect("Incorrect length"))?
                            }
                            else if prefix == PREFIX_PK_COMPRESSED_EVEN_Y || prefix ==  PREFIX_PK_COMPRESSED_ODD_Y {
                                // The below step implicitly checks that the pk is on the curve
                                PublicKey::parse_compressed(pk_bytes.as_slice().try_into().expect("Incorrect length"))?
                            }
                            else {
                                panic!("Unexpected prefix byte")
                            };
                            let pk_be = parsed_pk.serialize();
                            let pk_le = pk_bytes_swap_endianness(&pk_be[1..]);
                            let x = ct_option_ok_or(
                                secp256k1::Fp::from_bytes(pk_le[..32].try_into().unwrap()),
                                libsecp256k1::Error::InvalidPublicKey,
                            )?;
                            let y = ct_option_ok_or(
                                secp256k1::Fp::from_bytes(pk_le[32..].try_into().unwrap()),
                                libsecp256k1::Error::InvalidPublicKey,
                            )?;
                            let pk = ct_option_ok_or(
                                Secp256k1Affine::from_xy(x, y),
                                libsecp256k1::Error::InvalidPublicKey,
                            )?;
                            let pk_in_script = PublicKeyInScript {
                                bytes: pk_bytes,
                                pk
                            };
                            collected_keys.push(pk_in_script); // Add the public key to the list of collected keys
                            
                        },
                        _ => panic!("Expected public key bytes")
                    }
                    stack.remove(0); // Remove stack item corresponding to the valid signature
                    script_byte_index += 1;
                },
                Data(_) => {
                    panic!("Expected signature type");
                }
            }
        }
    }
    Ok(collected_keys)
}

#[cfg(test)]
mod tests {
    use crate::bitcoinvm_circuit::constants::*;
    use secp256k1::{self, Secp256k1, SecretKey, PublicKey};
    use secp256k1::constants::{UNCOMPRESSED_PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE};

    use super::{StackElement, collect_public_keys};

    #[test]
    fn test_pk_parser_compressed_pk() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes: [u8; PUBLIC_KEY_SIZE] = public_key.serialize();
        
        let mut script_pubkey: Vec<u8> = vec![];
        script_pubkey.push(PUBLIC_KEY_SIZE as u8); // "Push 33 bytes" opcode
        script_pubkey.extend(public_key_bytes.iter());
        script_pubkey.push(OP_CHECKSIG as u8);

        let initial_stack = vec![StackElement::ValidSignature];

        let collect_pks = collect_public_keys(script_pubkey, initial_stack).unwrap();
        assert_eq!(collect_pks.len(), 1);
        assert_eq!(collect_pks[0].bytes, public_key_bytes.to_vec());
    }

    #[test]
    fn test_pk_parser_uncompressed_pk() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes: [u8; UNCOMPRESSED_PUBLIC_KEY_SIZE] = public_key.serialize_uncompressed();
        
        let mut script_pubkey: Vec<u8> = vec![];
        script_pubkey.push(UNCOMPRESSED_PUBLIC_KEY_SIZE as u8); // "Push 65 bytes" opcode
        script_pubkey.extend(public_key_bytes.iter());
        script_pubkey.push(OP_CHECKSIG as u8);

        let initial_stack = vec![StackElement::ValidSignature];

        let collect_pks = collect_public_keys(script_pubkey, initial_stack).unwrap();
        assert_eq!(collect_pks.len(), 1);
        assert_eq!(collect_pks[0].bytes, public_key_bytes.to_vec());
    }

    #[test]
    fn test_pk_parser_multiple_keys() {
        let secp = Secp256k1::new();
        let secret_key1 = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key1 = PublicKey::from_secret_key(&secp, &secret_key1);
        let public_key_bytes1: [u8; PUBLIC_KEY_SIZE] = public_key1.serialize();

        let secret_key2 = SecretKey::from_slice(&[0xef; 32]).expect("32 bytes, within curve order");
        let public_key2 = PublicKey::from_secret_key(&secp, &secret_key2);
        let public_key_bytes2: [u8; PUBLIC_KEY_SIZE] = public_key2.serialize();

        let secret_key3 = SecretKey::from_slice(&[0xab; 32]).expect("32 bytes, within curve order");
        let public_key3 = PublicKey::from_secret_key(&secp, &secret_key3);
        let public_key_bytes3: [u8; UNCOMPRESSED_PUBLIC_KEY_SIZE] = public_key3.serialize_uncompressed();
        
        let mut script_pubkey: Vec<u8> = vec![];
        script_pubkey.push(PUBLIC_KEY_SIZE as u8); // "Push 33 bytes" opcode
        script_pubkey.extend(public_key_bytes1.iter());
        script_pubkey.push(OP_CHECKSIG as u8);

        script_pubkey.push(PUBLIC_KEY_SIZE as u8); // "Push 33 bytes" opcode
        script_pubkey.extend(public_key_bytes2.iter());
        script_pubkey.push(OP_CHECKSIG as u8);

        script_pubkey.push(UNCOMPRESSED_PUBLIC_KEY_SIZE as u8); // "Push 65 bytes" opcode
        script_pubkey.extend(public_key_bytes3.iter());
        script_pubkey.push(OP_CHECKSIG as u8);

        {
            let initial_stack = vec![
                StackElement::ValidSignature,
                StackElement::ValidSignature,
                StackElement::ValidSignature,
            ];

            let collect_pks = collect_public_keys(script_pubkey.clone(), initial_stack).unwrap();
            assert_eq!(collect_pks.len(), 3);
            assert_eq!(collect_pks[0].bytes, public_key_bytes1.to_vec());
            assert_eq!(collect_pks[1].bytes, public_key_bytes2.to_vec());
            assert_eq!(collect_pks[2].bytes, public_key_bytes3.to_vec());
        }

        {
            let initial_stack = vec![
                StackElement::InvalidSignature,
                StackElement::ValidSignature,
                StackElement::ValidSignature,
            ];

            let collect_pks = collect_public_keys(script_pubkey.clone(), initial_stack).unwrap();
            assert_eq!(collect_pks.len(), 2);
            assert_eq!(collect_pks[0].bytes, public_key_bytes2.to_vec());
            assert_eq!(collect_pks[1].bytes, public_key_bytes3.to_vec());
        }

        {
            let initial_stack = vec![
                StackElement::ValidSignature,
                StackElement::InvalidSignature,
                StackElement::ValidSignature,
            ];

            let collect_pks = collect_public_keys(script_pubkey.clone(), initial_stack).unwrap();
            assert_eq!(collect_pks.len(), 2);
            assert_eq!(collect_pks[0].bytes, public_key_bytes1.to_vec());
            assert_eq!(collect_pks[1].bytes, public_key_bytes3.to_vec());
        }

        {
            let initial_stack = vec![
                StackElement::ValidSignature,
                StackElement::ValidSignature,
                StackElement::InvalidSignature,
            ];

            let collect_pks = collect_public_keys(script_pubkey.clone(), initial_stack).unwrap();
            assert_eq!(collect_pks.len(), 2);
            assert_eq!(collect_pks[0].bytes, public_key_bytes1.to_vec());
            assert_eq!(collect_pks[1].bytes, public_key_bytes2.to_vec());
        }
    }

}