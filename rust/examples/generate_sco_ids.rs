use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde_json::Value;

fn main() {
    let valid_dir = Path::new("testdata/stix/valid/scos");
    for entry in fs::read_dir(valid_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let content = fs::read_to_string(&path).unwrap();
            let data: Value = serde_json::from_str(&content).unwrap();

            let obj_type = data["type"].as_str().unwrap();
            let mut props = HashMap::<String, Value>::new();

            // Extract id-contributing properties based on type
            match obj_type {
                "artifact" => {
                    if let Some(hashes) = data.get("hashes") {
                        if let Some(obj) = hashes.as_object() {
                            // Pick most preferred hash
                            let preferred = ["MD5", "SHA-1", "SHA-256", "SHA-512"];
                            let mut found = None;
                            for p in &preferred {
                                if let Some(v) = obj.get(*p) {
                                    found = Some((*p, v.clone()));
                                    break;
                                }
                            }
                            if let Some((k, v)) = found {
                                let mut h = HashMap::new();
                                h.insert(k.to_string(), v);
                                props.insert(
                                    "hashes".to_string(),
                                    Value::Object(h.into_iter().collect()),
                                );
                            } else if let Some((k, v)) = obj.iter().next() {
                                let mut h = HashMap::new();
                                h.insert(k.clone(), v.clone());
                                props.insert(
                                    "hashes".to_string(),
                                    Value::Object(h.into_iter().collect()),
                                );
                            }
                        }
                    }
                    if let Some(v) = data.get("payload_bin") {
                        props.insert("payload_bin".to_string(), v.clone());
                    }
                }
                "autonomous-system" => {
                    if let Some(v) = data.get("number") {
                        props.insert("number".to_string(), v.clone());
                    }
                }
                "directory" => {
                    if let Some(v) = data.get("path") {
                        props.insert("path".to_string(), v.clone());
                    }
                }
                "domain-name" | "email-addr" | "ipv4-addr" | "ipv6-addr" | "mac-addr" | "url" => {
                    if let Some(v) = data.get("value") {
                        props.insert("value".to_string(), v.clone());
                    }
                }
                "email-message" => {
                    if let Some(v) = data.get("from_ref") {
                        props.insert("from_ref".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("subject") {
                        props.insert("subject".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("body") {
                        props.insert("body".to_string(), v.clone());
                    }
                }
                "file" => {
                    if let Some(hashes) = data.get("hashes") {
                        if let Some(obj) = hashes.as_object() {
                            let preferred = ["MD5", "SHA-1", "SHA-256", "SHA-512"];
                            let mut found = None;
                            for p in &preferred {
                                if let Some(v) = obj.get(*p) {
                                    found = Some((*p, v.clone()));
                                    break;
                                }
                            }
                            if let Some((k, v)) = found {
                                let mut h = HashMap::new();
                                h.insert(k.to_string(), v);
                                props.insert(
                                    "hashes".to_string(),
                                    Value::Object(h.into_iter().collect()),
                                );
                            } else if let Some((k, v)) = obj.iter().next() {
                                let mut h = HashMap::new();
                                h.insert(k.clone(), v.clone());
                                props.insert(
                                    "hashes".to_string(),
                                    Value::Object(h.into_iter().collect()),
                                );
                            }
                        }
                    }
                    if let Some(v) = data.get("name") {
                        props.insert("name".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("extensions") {
                        props.insert("extensions".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("parent_directory_ref") {
                        props.insert("parent_directory_ref".to_string(), v.clone());
                    }
                }
                "network-traffic" => {
                    if let Some(v) = data.get("protocols") {
                        props.insert("protocols".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("start") {
                        props.insert("start".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("end") {
                        props.insert("end".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("src_ref") {
                        props.insert("src_ref".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("dst_ref") {
                        props.insert("dst_ref".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("src_port") {
                        props.insert("src_port".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("dst_port") {
                        props.insert("dst_port".to_string(), v.clone());
                    }
                    if let Some(v) = data.get("extensions") {
                        props.insert("extensions".to_string(), v.clone());
                    }
                }
                "software" => {
                    if let Some(v) = data.get("name") {
                        props.insert("name".to_string(), v.clone());
                    }
                }
                "windows-registry-key" => {
                    if let Some(v) = data.get("values") {
                        props.insert("values".to_string(), v.clone());
                    }
                }
                _ => {}
            }

            // Empty map means no contributing properties were found
            let canon = json_canon::to_vec(&props).unwrap();
            println!(
                "{}: {} -> {:?}",
                path.file_name().unwrap().to_str().unwrap(),
                obj_type,
                canon
            );
        }
    }
}
