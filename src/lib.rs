
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
    use base64::decode;

    #[derive(Debug, Clone, sqlx::FromRow)]
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

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ApiAdmin {
        pub u_name: String,
        pub is_root: bool,
    }

    impl From<Admin> for ApiAdmin {
        fn from(Admin { u_name, is_root, .. }: Admin) -> Self {
            ApiAdmin { u_name, is_root }
        }
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct AdminPassword {
        pub id: Uuid,
        pub password_hash: Vec<u8>,
        pub salt: Vec<u8>,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
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

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ApiInterface {
        pub u_name: String,
        pub public_key: Option<String>,
        pub port: Option<i32>,
        pub ip: Option<IpNetwork>,
        pub fqdn: Option<String>,
    }

    impl From<Interface> for ApiInterface {
        fn from(Interface { u_name, public_key, port, ip, fqdn, .. }: Interface) -> Self {
            ApiInterface {u_name, public_key, port, ip, fqdn,}
        }
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct InterfacePassword {
        pub id: Uuid,
        pub password_hash: Vec<u8>,
        pub salt: Vec<u8>,
    }

    #[derive(Debug, Clone, sqlx::FromRow)]
    pub struct PeerRelation {
        pub endpoint_id: Uuid,
        pub peer_id: Uuid,
        pub peer_name: String,
        pub endpoint_name: String,
        pub endpoint_allowed_ip: Vec<IpNetwork>,
        pub peer_allowed_ip: Vec<IpNetwork>,
    }

    impl From<ApiPeerRelation> for PeerRelation {
        fn from(ApiPeerRelation { peer_name, endpoint_name, endpoint_allowed_ip, peer_allowed_ip, }: ApiPeerRelation) -> Self {
            PeerRelation { endpoint_id: Default::default(), peer_id: Default::default(), peer_name, endpoint_name, endpoint_allowed_ip, peer_allowed_ip, }
        }
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct ApiPeerRelation {
        pub endpoint_name: String,
        pub peer_name: String,
        pub endpoint_allowed_ip: Vec<IpNetwork>,
        pub peer_allowed_ip: Vec<IpNetwork>,
    }
    
    impl From<PeerRelation> for ApiPeerRelation {
        fn from(PeerRelation { peer_name, endpoint_name, endpoint_allowed_ip, peer_allowed_ip, .. }: PeerRelation) -> Self {
            ApiPeerRelation { peer_name, endpoint_name, endpoint_allowed_ip, peer_allowed_ip, }
        }
    }

    #[derive(Debug, Default, Clone)]
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


    #[derive(Debug, Clone)]
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

#[cfg(test)]
mod testd {
    use auth::verify;

    use super::*;

    #[test]
    fn test_inverse_auth() {
        // assert_eq!(add(1, 2), 3);

        let h1: auth::Hash = auth::encrypt("poopoo").unwrap();
        auth::verify(&h1, "poopoo").unwrap();
    }
}
