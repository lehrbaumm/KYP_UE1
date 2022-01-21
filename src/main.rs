extern crate pcarp;
extern crate regex;

mod network;
mod sec_tunnel;

use pcarp::Capture;
use std::fs::File;
use network::ip::*;
use network::ethernet::*;
use network::tcp::*;
use sec_tunnel::*;
use regex::Regex;
use std::io::{BufRead, BufReader};


fn main() {
    let file = File::open("message.pcapng").unwrap();
    let mut pcap = Capture::new(file).unwrap();
    let mut message_counter = 0;
    let mut configuration: SecureTunnelConfig = Default::default();
    let mut data: Vec<SecureTunnelPayload> = Vec::new();
    
    // Parsen der Pakete aus PCAP File
    while let Some(pkt) = pcap.next() {
        println!("");
        let pkt = pkt.unwrap();
        
        let eth_header = EthernetHeader::new(&pkt.data);
        
        let ip_header = match eth_header.ether_type {
            0x0800 => IPHeader::V4(IP4Header::new(&pkt.data)),
            0x86DD => IPHeader::V6(IP6Header::new(&pkt.data)),
            _ => panic!("Not yet implemented"),
        };

        let tcp_header = match ip_header.get_protocol() {
            6 => TCPHeader::new(&pkt.data),
            //17 => write!(f, "UDP\t"),
            _ => panic!("Not yet implemented {}", ip_header.get_protocol()),
        };

        if tcp_header.flags == 0x18 {
            println!("Ethernet: \n{}\n", eth_header);
            println!("IP: \n{}\n", ip_header);
            println!("TCP: \n{}\n", tcp_header);
        } else {
            continue;
        }

        let mut tunnel_header: SecureTunnelHeader = Default::default();
        tunnel_header.sender = String::new();
        tunnel_header.receiver = String::new();
        let mut counter: usize = pkt.data.len()-tcp_header.payload_length;
        if counter == pkt.data.len() {
            continue;
        } else if counter+1 == pkt.data.len() {
            println!("Data: {}", pkt.data[counter] as char);
            continue;
        }
        loop {
            let c = pkt.data[counter] as char;
            if c == '>' {
                counter += 1;
                break;
            }
            tunnel_header.sender.push(c);
            counter += 1;
        }
        loop {
            let c = pkt.data[counter] as char;
            if c == '(' {
                counter += 1;
                break;
            }
            tunnel_header.receiver.push(c);
            counter += 1;
        }
        let data_size = format!("{}{}", pkt.data[counter] as char, pkt.data[counter+1] as char);
        tunnel_header.len = usize::from_str_radix(&data_size, 16).unwrap();
        counter += 3;
        println!("Secure Tunnel Header:\n{}", tunnel_header);
        if counter+tunnel_header.len != pkt.data.len() {
            panic!("Wrong Tunnel Length!");
        }

        if message_counter == 0 {
            loop {
                let c = pkt.data[counter] as char;
                if c == ':' {
                    counter += 1;
                    break;
                }
                configuration.header.push(c);
                counter += 1;
            }
            let packet_count = format!("{}{}", pkt.data[counter] as char, pkt.data[counter+1] as char);
            configuration.count = u32::from_str_radix(&packet_count, 10).unwrap();
            counter += 3;
            configuration.nonce.clone_from_slice(&pkt.data[counter..counter+8]);
            counter += 9;
            configuration.tail = format!("{}{}", pkt.data[counter] as char, pkt.data[counter+1] as char);
            counter += 2;
            println!("Configuration:\n{}", configuration);
        
        } else {
            let mut buffer: SecureTunnelPayload = Default::default();
            
            loop {
                let c = pkt.data[counter] as char;
                if c == ':' {
                    counter += 1;
                    break;
                }
                buffer.header.push(c);
                counter += 1;
            }

            let mut count_buffer = String::new();
            loop {
                let c = pkt.data[counter] as char;
                if c == ':' {
                    counter += 1;
                    break;
                }
                count_buffer.push(c);
                counter += 1;
            }
            buffer.counter = u32::from_str_radix(&count_buffer, 10).unwrap();
            if buffer.counter != message_counter - 1 {
                panic!("Missed Package!");
            }
            //Check if ":" is part of ciphertext
            let mut count_column = 0;
            for i in counter..pkt.data.len() {
                let c = pkt.data[i] as char;
                if c == ':' {
                    count_column += 1;
                }
            }

            buffer.ciphertext = Vec::new();
            loop {
                let c = pkt.data[counter] as char;
                if c == ':' && count_column == 2 {
                    counter += 1;
                    break;
                } else if c == ':' {
                    count_column -= 1;
                }
                buffer.ciphertext.push(pkt.data[counter]);
                counter += 1;
            }

            buffer.tail = format!("{}{}", pkt.data[counter] as char, pkt.data[counter+1] as char);
            counter += 3;

            buffer.hmac.clone_from_slice(&pkt.data[counter..counter+16]);
            counter+=16;
            println!("SecTunnel Data:\n{}", buffer);

            data.push(buffer);
        }

        if counter != pkt.data.len() {
            panic!("Error, length doesn't match count of parsed bytes!");
        }
        message_counter += 1;
    } if data.len() != configuration.count as usize {
        panic!("Not Enough Packages were parsed!");
    }

    //Vorbereiten von Variablen
    let mut text_size = 0;
    let mut tst: Vec<Vec<u8>> = Vec::new();
    let mut cipher_key: Vec<u8> = Vec::new();
    let mut plaintext = Vec::new();
    for _ in 0..data[0].ciphertext.len() {
        tst.push(Vec::new());
        cipher_key.push(0xFF);
    } for i in 0..data.len() {
        text_size += data[i].ciphertext.len();
        print!("Ciphertext {:02}: ", i);
        for j in 0..data[i].ciphertext.len() {
            print!("{:02X} ", data[i].ciphertext[j]);
            tst[j].push(data[i].ciphertext[j]);
        }
        println!("");
    } for _ in 0..text_size {
        plaintext.push(35);
    } 


    //Suche nach Leerzeichen und gleichen Zeichen
    for i in 0..tst.len() {
        for j in 0..tst[i].len() {
            for k in 0..tst[i].len() {
                if j == k {
                    continue;
                }
                let buf = tst[i][j] ^ tst[i][k];
                if buf <= 'z' as u8 && buf >= 'a' as u8 {
                    let plain = (tst[i][j] ^ 0x20)^tst[i][k];
                    if plain < 'Z' as u8 && plain > 'A' as u8 {
                        let key = tst[i][j] ^ 0x20;
                        let mut check_counter = 0;
                        for m in 0..tst[i].len() {
                            let plain = key ^ tst[i][m];
                            if plain <= 'Z' as u8 && plain >= 'A' as u8 {
                                check_counter += 1;
                            }
                            if plain <= 'z' as u8 && plain >= 'a' as u8 {
                                check_counter += 1;
                            }
                            if plain == 0x20 {
                                check_counter += 1;
                            }
                        }
                        if check_counter == tst[i].len() {
                            cipher_key[i] = key;
                        }
                    }
                } else if buf <= 'Z' as u8 && buf >= 'A' as u8 {
                    let plain = (tst[i][j] ^ 0x20)^tst[i][k];
                    if plain < 'z' as u8 && plain > 'a' as u8 {
                        let key = tst[i][j] ^ 0x20;
                        let mut check_counter = 0;
                        for m in 0..tst[i].len() {
                            let plain = key ^ tst[i][m];
                            if plain <= 'Z' as u8 && plain >= 'A' as u8 {
                                check_counter += 1;
                            }
                            if plain <= 'z' as u8 && plain >= 'a' as u8 {
                                check_counter += 1;
                            }
                            if plain == 0x20 {
                                check_counter += 1;
                            }
                        }
                        if check_counter == tst[i].len() {
                            cipher_key[i] = key;
                        }
                    }
                } else if buf == 0x00 {
                    if cipher_key[i] == 0xFF {
                        let key = tst[i][j] ^ 0x20;
                        let mut valid = true;
                        for m in 0..tst[i].len() {
                            let buf = tst[i][m] ^ key;
                            if !(buf <= 'Z' as u8 && buf >= 'A' as u8) && !(buf <= 'z' as u8 && buf >= 'a' as u8) && !(buf == 0x20) {
                                valid = false;
                                break;
                            }
                        }
                        if valid {
                            cipher_key[i] = key;
                        }
                    }
                }
            }
        }
    }

    //Entschlüsseln mit partiellen Schlüssel
    println!("Cipher Key: {:02X?}", cipher_key);
    for i in 0..data.len() {
        for j in 0..data[i].ciphertext.len() {
            if cipher_key[j] != 0xFF {
                plaintext[i*data[0].ciphertext.len()+j] = data[i].ciphertext[j] ^ cipher_key[j];
            }
        }
    }
    for i in 0..plaintext.len() {
        let c = plaintext[i] as char;
        if (i) % data[0].ciphertext.len() == 0 {
            println!("");
        }
        print!("{}", c);
    }
    println!("");

    //Wordlist Attack on missing keys.
    let mut used_indexes: Vec<usize> = Vec::new();
    for i in 0..data[0].ciphertext.len() {
        if plaintext[i] == 35 {
            let mut missing_word = String::new();
            let mut start = i;
            for j in (0..i).rev() {
                if plaintext[j] == 0x20 {
                    break;
                }
                start = i;
            }
            if used_indexes.contains(&start) {
                continue;
            }
            let mut end = start;
            for j in start..data[0].ciphertext.len() {
                used_indexes.push(j);
                if plaintext[j] == 0x20 {
                    break;
                }
                end = j;
                missing_word.push(plaintext[j] as char);
            }
            missing_word = missing_word.replace('#', ".");
            let missing_count = missing_word.matches(".").count();
            if start == 0 {
                missing_word = format!("[A-Z]{}", missing_word.chars().next().map(|c| &missing_word[c.len_utf8()..]).unwrap_or(""));
            }
            let word_regex = format!("^{}$", missing_word);
            let re = Regex::new(&word_regex).unwrap();
            let file = File::open("wordlist.txt").unwrap();
            for line in BufReader::new(file).lines() {
                let possible_word = match line {
                    Ok(data) => data,
                    Err(err) => panic!("Error reading line from File: {:?}", err)
                };
                if re.is_match(&possible_word) {
                    let mut valid = 0;
                    for j in start..=end {
                        if plaintext[j] == 35 {
                            let key = tst[j][0] ^ possible_word.bytes().nth(j-start).unwrap();
                            let mut is_valid = true;
                            for k in 1..tst[j].len() {
                                let buf = tst[j][k] ^ key;
                                if !(buf <= 'Z' as u8 && buf >= 'A' as u8) && !(buf <= 'z' as u8 && buf >= 'a' as u8) {
                                    is_valid = false;
                                    break;
                                }
                            }
                            if is_valid {
                                valid += 1;
                            } else {
                                valid = 0;
                            }
                        }
                    }
                    if valid == missing_count {
                        for j in start..=end {
                            if plaintext[j] == 35 {
                                let key = tst[j][0] ^ possible_word.bytes().nth(j-start).unwrap();
                                cipher_key[j] = key;
                            }                            
                        }
                        break;
                    }
                }
            }
        }
    }

    //Erster Funktioniert nicht, da Hiebe neben Liebe als möglicher Plaintext geht.
    cipher_key[0] = 0x72;
    println!("Cipher Key: {:02X?}", cipher_key);
    println!("");

    //Vollständig entschlüsseln
    for i in 0..data.len() {
        for j in 0..data[i].ciphertext.len() {
            if cipher_key[j] != 0xFF {
                plaintext[i*data[0].ciphertext.len()+j] = data[i].ciphertext[j] ^ cipher_key[j];
            }
        }
    }
    for i in 0..plaintext.len() {
        let c = plaintext[i] as char;
        if (i) % data[0].ciphertext.len() == 0 {
            println!("");
        }
        print!("{}", c);
    }
    println!("");
}
