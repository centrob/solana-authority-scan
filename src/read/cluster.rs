//! Clusters, their genesis hashes, and the check that an endpoint is on the cluster the
//! caller asked for. The check runs before any other call (`HttpRpc::connect`).

use crate::read::rpc::{Rpc, RpcError};

/// A public Solana cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cluster {
    Mainnet,
    Devnet,
    Testnet,
}

impl Cluster {
    pub const ALL: [Self; 3] = [Self::Mainnet, Self::Devnet, Self::Testnet];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
        }
    }

    /// The cluster's genesis hash, as `getGenesisHash` returns it.
    pub const fn genesis_hash(self) -> &'static str {
        match self {
            Self::Mainnet => "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
            Self::Devnet => "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
            Self::Testnet => "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
        }
    }

    /// The environment variable that holds this cluster's RPC URL.
    pub const fn rpc_url_var(self) -> &'static str {
        match self {
            Self::Mainnet => "SOLANA_MAINNET_RPC_URL",
            Self::Devnet => "SOLANA_DEVNET_RPC_URL",
            Self::Testnet => "SOLANA_TESTNET_RPC_URL",
        }
    }
}

/// Refuses an endpoint whose genesis hash is not `cluster`'s.
pub fn check_cluster<R: Rpc + ?Sized>(rpc: &R, cluster: Cluster) -> Result<(), RpcError> {
    let found = rpc.get_genesis_hash()?;
    if found.to_string() == cluster.genesis_hash() {
        Ok(())
    } else {
        Err(RpcError::WrongCluster {
            expected: cluster,
            found,
        })
    }
}

/// `rpc`, once its endpoint is checked to be on `cluster`. The genesis hash is the first
/// call made through `rpc`; on a mismatch `rpc` is dropped, so no other read can happen.
/// `HttpRpc::connect` is this over a fresh `HttpRpc`; another transport uses it the same
/// way.
pub fn checked<R: Rpc>(rpc: R, cluster: Cluster) -> Result<R, RpcError> {
    check_cluster(&rpc, cluster)?;
    Ok(rpc)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::read::codec::{Address, Hash, Signature};
    use crate::read::rpc::{
        Account, KeyedAccount, ProgramAccountsQuery, SignatureInfo, SignaturesQuery, Slotted,
        TransactionRecord,
    };

    /// Answers the genesis hash and records every call, in order. Other reads fail.
    struct Recorder {
        genesis: Hash,
        calls: RefCell<Vec<&'static str>>,
    }

    impl Recorder {
        fn new(genesis: Hash) -> Self {
            Self {
                genesis,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn read<T>(&self, name: &'static str) -> Result<T, RpcError> {
            self.calls.borrow_mut().push(name);
            Err(RpcError::BadRequest(
                "the recorder answers only the genesis hash",
            ))
        }

        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }

    impl Rpc for Recorder {
        fn get_genesis_hash(&self) -> Result<Hash, RpcError> {
            self.calls.borrow_mut().push("get_genesis_hash");
            Ok(self.genesis)
        }
        fn get_account_info(&self, _: &Address) -> Result<Slotted<Option<Account>>, RpcError> {
            self.read("get_account_info")
        }
        fn get_multiple_accounts(
            &self,
            _: &[Address],
        ) -> Result<Slotted<Vec<Option<Account>>>, RpcError> {
            self.read("get_multiple_accounts")
        }
        fn get_program_accounts(
            &self,
            _: &Address,
            _: &ProgramAccountsQuery,
        ) -> Result<Slotted<Vec<KeyedAccount>>, RpcError> {
            self.read("get_program_accounts")
        }
        fn get_signatures_for_address(
            &self,
            _: &Address,
            _: &SignaturesQuery,
        ) -> Result<Vec<SignatureInfo>, RpcError> {
            self.read("get_signatures_for_address")
        }
        fn get_transaction(&self, _: &Signature) -> Result<Option<TransactionRecord>, RpcError> {
            self.read("get_transaction")
        }
    }

    fn hash_of(cluster: Cluster) -> Hash {
        cluster.genesis_hash().parse().unwrap()
    }

    /// `HttpRpc::connect` is `checked` over a new `HttpRpc`, so this is its order.
    #[test]
    fn checked_asks_for_the_genesis_hash_first_and_only() {
        let rpc = checked(Recorder::new(hash_of(Cluster::Devnet)), Cluster::Devnet).unwrap();
        assert_eq!(rpc.calls(), ["get_genesis_hash"]);
        let _ = rpc.get_account_info(&Address::new([0; 32]));
        assert_eq!(rpc.calls(), ["get_genesis_hash", "get_account_info"]);

        let wrong = Recorder::new(hash_of(Cluster::Devnet));
        assert!(matches!(
            check_cluster(&wrong, Cluster::Mainnet),
            Err(RpcError::WrongCluster { .. })
        ));
        assert_eq!(wrong.calls(), ["get_genesis_hash"]);
        assert!(checked(wrong, Cluster::Mainnet).is_err());
    }

    #[test]
    fn every_genesis_hash_is_32_bytes_and_distinct() {
        for a in Cluster::ALL {
            for b in Cluster::ALL {
                assert_eq!(a == b, hash_of(a) == hash_of(b), "{a:?} {b:?}");
            }
        }
    }

    #[test]
    fn accepts_the_matching_cluster() {
        for cluster in Cluster::ALL {
            assert_eq!(
                check_cluster(&Recorder::new(hash_of(cluster)), cluster),
                Ok(())
            );
        }
    }

    #[test]
    fn refuses_a_genesis_mismatch() {
        let devnet = Recorder::new(hash_of(Cluster::Devnet));
        let error = check_cluster(&devnet, Cluster::Mainnet).unwrap_err();
        assert_eq!(
            error,
            RpcError::WrongCluster {
                expected: Cluster::Mainnet,
                found: hash_of(Cluster::Devnet),
            }
        );
        assert!(error.to_string().contains("not on mainnet"), "{error}");
        let other = Recorder::new(Hash::new([9; 32]));
        assert!(check_cluster(&other, Cluster::Devnet).is_err());
    }
}
