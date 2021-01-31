
pub mod config {
    use std::env::{var, VarError};
    #[derive(Debug)]
    pub struct DbCfg {
        pub host: String,
        pub user: String,
        pub pw: String,
        pub port: String,
        pub name: String,
    }
    
    #[derive(Debug)]
    pub struct ApiCfg {
        pub port: String,
        pub ip: String,
    }
    
    pub fn get_db_cfg() -> Result<DbCfg, VarError> {
        Ok(DbCfg {
            host: var("WGMAN_DB_HOST")?,
            user: var("WGMAN_DB_USER")?,
            pw: var("WGMAN_DB_PW")?,
            port: var("WGMAN_DB_PORT")?,
            name: var("WGMAN_DB_NAME")?,
        })
    }
    
    pub fn get_api_cfg() -> Result<ApiCfg, VarError> {
        Ok(ApiCfg {
            port: var("WGMAN_API_PORT")?,
            ip: var("WGMAN_API_IP")?,
        })
    }    
}

pub mod types {
    use std::{convert::TryFrom, error::Error, str::FromStr};

    use ring::error::Unspecified;
    use serde::{ Deserialize, Serialize };
    use ipnetwork::IpNetwork;
    use uuid::Uuid;
    use base64::{encode, decode};
    use std::fmt;

    use crate::auth::encrypt;

    #[derive(PartialEq, Eq, Debug, Clone, sqlx::FromRow)]
    pub struct Admin {
        pub id: Uuid,
        pub u_name: String,
        pub is_root: bool,
    }

    impl TryFrom<ApiAdmin> for Admin {
        type Error = ring::error::Unspecified;

        fn try_from(ApiAdmin{ u_name, is_root }: ApiAdmin) -> Result<Self, Self::Error> {
            match u_name {
                s if s.contains(":") => Err(Unspecified),
                _ => Ok(Admin {
                    id: (Default::default()),
                    u_name,
                    is_root,
                })
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct ApiAdmin {
        pub u_name: String,
        pub is_root: bool,
    }

    impl From<Admin> for ApiAdmin {
        fn from(Admin { u_name, is_root, .. }: Admin) -> Self {
            ApiAdmin { u_name, is_root }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, sqlx::FromRow)]
    pub struct AdminPassword {
        pub id: Uuid,
        pub u_name: String,
        pub password_hash: Vec<u8>,
        pub salt: Vec<u8>,
    }

    #[derive(PartialEq, Eq, Debug, Clone, sqlx::FromRow)]
    pub struct Interface {
        pub id: Uuid,
        pub u_name: String,
        pub public_key: Option<String>,
        pub port: Option<i32>,
        pub ip: Option<IpNetwork>,
        pub fqdn: Option<String>,
    }

    impl TryFrom<ApiInterface> for Interface {
        type Error = ring::error::Unspecified;

        fn try_from(ApiInterface { u_name, public_key, port, ip, fqdn }: ApiInterface) -> Result<Self, Self::Error> {
            match u_name {
                s if s.contains(":") => Err(Unspecified),
                _ => Ok(Interface {
                    id: Default::default(),
                    u_name,
                    public_key,
                    port,
                    ip,
                    fqdn,
                })
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct ApiInterface {
        pub u_name: String,
        pub public_key: Option<String>,
        pub port: Option<i32>,
        pub ip: Option<IpNetwork>,
        pub fqdn: Option<String>,
    }

    impl ApiInterface {
        pub fn coallesce(&mut self, other: Self) {
            match other.public_key {
                Some(v) => self.public_key = Some(v),
                None => {}
            };
            match other.port {
                Some(v) => self.port = Some(v),
                None => {}
            };
            match other.ip {
                Some(v) => self.ip = Some(v),
                None => {}
            };
            match other.fqdn {
                Some(v) => self.fqdn = Some(v),
                None => {}
            };
        }
    }

    impl From<Interface> for ApiInterface {
        fn from(Interface { u_name, public_key, port, ip, fqdn, .. }: Interface) -> Self {
            ApiInterface {u_name, public_key, port, ip, fqdn,}
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, sqlx::FromRow)]
    pub struct InterfacePassword {
        pub id: Uuid,
        pub u_name: String,
        pub password_hash: Vec<u8>,
        pub salt: Vec<u8>,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct ApiInterfacePassword {
        pub u_name: String,
        pub password: String,
    }

    impl TryFrom<ApiInterfacePassword> for InterfacePassword {
        type Error = ring::error::Unspecified;

        fn try_from(ApiInterfacePassword { u_name, password }: ApiInterfacePassword) -> Result<Self, Self::Error> {
            let hash = encrypt(&password)?;
            Ok(InterfacePassword {
                    id: Default::default(),
                    u_name,
                    password_hash: hash.pbkdf2_hash.into(),
                    salt: hash.salt.into(),
            })
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct ApiAdminPassword {
        pub u_name: String,
        pub password: String,
    }

    impl TryFrom<ApiAdminPassword> for AdminPassword {
        type Error = ring::error::Unspecified;

        fn try_from(ApiAdminPassword { u_name, password }: ApiAdminPassword) -> Result<Self, Self::Error> {
            let hash = encrypt(&password)?;
            Ok(AdminPassword {
                    id: Default::default(),
                    u_name,
                    password_hash: hash.pbkdf2_hash.into(),
                    salt: hash.salt.into(),
            })
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, sqlx::FromRow)]
    pub struct PeerRelation {
        pub endpoint_id: Uuid,
        pub peer_id: Uuid,
        pub peer_public_key: String,
        pub endpoint_public_key: String,
        pub endpoint_allowed_ip: Option<Vec<IpNetwork>>,
        pub peer_allowed_ip: Option<Vec<IpNetwork>>,
    }

    impl From<ApiPeerRelation> for PeerRelation {
        fn from(ApiPeerRelation { peer_public_key, endpoint_public_key, endpoint_allowed_ip, peer_allowed_ip, }: ApiPeerRelation) -> Self {
            PeerRelation { endpoint_id: Default::default(), peer_id: Default::default(), peer_public_key, endpoint_public_key, endpoint_allowed_ip, peer_allowed_ip, }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct ApiPeerRelation {
        pub endpoint_public_key: String,
        pub peer_public_key: String,
        pub endpoint_allowed_ip: Option<Vec<IpNetwork>>,
        pub peer_allowed_ip: Option<Vec<IpNetwork>>,
    }
    
    impl From<PeerRelation> for ApiPeerRelation {
        fn from(PeerRelation { peer_public_key, endpoint_public_key, endpoint_allowed_ip, peer_allowed_ip, .. }: PeerRelation) -> Self {
            ApiPeerRelation { peer_public_key, endpoint_public_key, endpoint_allowed_ip, peer_allowed_ip, }
        }
    }

    impl ApiPeerRelation {
        pub fn coallesce(&mut self, other: Self) {
            match other.endpoint_allowed_ip {
                Some(allowed_ip) => self.endpoint_allowed_ip = Some(allowed_ip),
                None => {}
            };
            match other.peer_allowed_ip {
                Some(allowed_ip) => self.peer_allowed_ip = Some(allowed_ip),
                None => {}
            };
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct InterfaceConfigPeer {
        pub public_key: String,
        pub allowed_ip: Vec<IpNetwork>,
        pub endpoint: Option<String>
    }
    
    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct InterfaceConfig {
        pub interface: ApiInterface,
        pub peers: Vec<InterfaceConfigPeer>
    }
    
    #[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
    pub struct ApiConfig {
        pub interface: ApiInterface,
        pub peers: Vec<ApiPeerRelation>
    }
    
    impl From<InterfaceConfig> for ApiConfig {
        fn from(InterfaceConfig { interface, peers } : InterfaceConfig) -> Self {
            Self {
                interface: interface.clone(),
                peers: peers.iter().map(|p| match &p.endpoint {
                    Some(_) => ApiPeerRelation {
                            endpoint_public_key: p.public_key.clone(),
                            peer_public_key: interface.public_key.as_ref().unwrap().to_string(),
                            endpoint_allowed_ip: None,
                            peer_allowed_ip: Some(p.allowed_ip.clone()),
                        },
                    None => ApiPeerRelation {
                            endpoint_public_key: interface.public_key.as_ref().unwrap().to_string(),
                            peer_public_key: p.public_key.clone(),
                            endpoint_allowed_ip: Some(p.allowed_ip.clone()),
                            peer_allowed_ip: None,
                        }
                })
                .collect(),
            }
        }
    }
    
    pub enum InterfaceConfigBlockKind {
        Interface,
        Peer
    }

    #[derive(PartialEq, Eq, Debug, Default, Clone)]
    pub struct BasicAuth {
        pub name: String,
        pub password: String
    }

    // Warning:: only intended to be used with base64 authorization header
    impl FromStr for BasicAuth {
        type Err = Box<dyn Error>;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match &s[..5] {
                "Basic" => {
                    let decoded = decode(&s[6..])?;
                    let auth_string = std::str::from_utf8(&decoded[..])?;
                    let colon_indx = match auth_string.find(":") {
                        Some(indx) => {
                            if indx < auth_string.len() - 1 {
                                indx
                            }
                            else {
                                Err("Invalid Login")?
                            }
                        },
                        None => {Err("Invalid Login")?}
                    };

                    Ok(BasicAuth { name: auth_string[..colon_indx].into(), password: auth_string[colon_indx + 1..].into() })
                        
                }
                _ => Err("Invalid Login")?
            }
        }
    }

    // Warning:: only intended to be used with base64 authorization header
    impl fmt::Display for BasicAuth {
        // This trait requires `fmt` with this exact signature.
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // Write strictly the first element into the supplied output
            // stream: `f`. Returns `fmt::Result` which indicates whether the
            // operation succeeded or failed. Note that `write!` uses syntax which
            // is very similar to `println!`.
            let encoded_auth = encode(format!("{}:{}", self.name, self.password));
            write!(f, "Basic {}", encoded_auth)
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone)]
    pub enum AuthKind {
        Admin,
        Interface,
    }

    impl Default for AuthKind {
        fn default() -> Self {
            AuthKind::Admin
        }
    }
}

pub mod auth {
    use ring::error::Unspecified;
    use ring::rand::SecureRandom;
    use ring::{digest, pbkdf2, rand};
    use std::num::NonZeroU32;

    pub struct Hash {
        pub pbkdf2_hash: [u8; digest::SHA512_OUTPUT_LEN],
        pub salt: [u8; digest::SHA512_OUTPUT_LEN],
    }
    
    pub fn encrypt(password: &str) -> Result<Hash, Unspecified> {
        const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
        let n_iter = NonZeroU32::new(100_000).unwrap();
        let rng = rand::SystemRandom::new();
    
        let mut salt = [0u8; CREDENTIAL_LEN];
        rng.fill(&mut salt)?;
    
        let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            n_iter,
            &salt,
            password.as_bytes(),
            &mut pbkdf2_hash,
        );
    
        Ok(Hash { salt, pbkdf2_hash })
    }
    
    pub fn verify(Hash { salt, pbkdf2_hash }: &Hash, password: &str) -> Result<(), Unspecified> {
        let n_iter = NonZeroU32::new(100_000).unwrap();    
        pbkdf2::verify(
            pbkdf2::PBKDF2_HMAC_SHA512,
            n_iter,
            salt,
            password.as_bytes(),
            pbkdf2_hash,
        )
    }
}

// TODO add unit tests validation functions
#[cfg(test)]
mod tests {
    use auth::verify;

    use super::*;

    #[test]
    fn test_inverse_auth() {
        // assert_eq!(add(1, 2), 3);

        let h1: auth::Hash = auth::encrypt("poopoo").unwrap();
        auth::verify(&h1, "poopoo").unwrap();
    }
}
