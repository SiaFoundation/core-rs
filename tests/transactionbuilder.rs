extern crate sia_core;

use sia_core::transactionbuilder::*;
use sia_core::transactions::Transaction;

#[test]
fn test_transactionbuilder_new() {
    let transaction = TransactionBuilder::new().finalize();
    assert_eq!(transaction, Transaction::default());
}
