//! Boundary cases for the paginated alert queries (#265).
//!
//! Five alerts are registered for one target contract, labelled `a0`..`a4` in ID order, so each
//! page can be checked by content, not only by length. `limit = MAX_BATCH_SIZE + 1` is clamped
//! to `MAX_BATCH_SIZE` — the paginated functions silently cap the effective limit (#209).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

use crate::{AlertRegistry, AlertRegistryClient, MAX_BATCH_SIZE};

fn hash64(env: &Env) -> String {
    String::from_str(env, "a3f1b2c4d5e6f7089abcdef01234567890abcdef01234567890abcdef012345")
}

fn setup() -> (Env, AlertRegistryClient<'static>, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);

    let querier = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);
    // Labels a0..a4 in ID order — used by page-content assertions below.
    let labels = ["a0", "a1", "a2", "a3", "a4"];
    for label_str in labels {
        let label = String::from_str(&env, label_str);
        client.register_alert(
            &owner,
            &target,
            &label,
            &String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &vec![&env, String::from_str(&env, "rule:transfer")],
            &None,
        );
    }
    (env, client, querier, target)
}

#[test]
fn empty_index_returns_an_empty_page() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);
    let querier = Address::generate(&env);
    let target = Address::generate(&env);
    let page = client.try_get_contract_alerts_paginated(&querier, &target, &0, &10).unwrap().unwrap();
    assert_eq!(page.len(), 0);
}

#[test]
fn first_and_second_pages_hold_the_expected_alerts() {
    let (env, client, querier, target) = setup();

    let first = client.try_get_contract_alerts_paginated(&querier, &target, &0, &3).unwrap().unwrap();
    assert_eq!(first.len(), 3);
    assert_eq!(first.get(0).unwrap().label, String::from_str(&env, "a0"));
    assert_eq!(first.get(2).unwrap().label, String::from_str(&env, "a2"));

    let second = client.try_get_contract_alerts_paginated(&querier, &target, &3, &3).unwrap().unwrap();
    assert_eq!(second.len(), 2);
    assert_eq!(second.get(0).unwrap().label, String::from_str(&env, "a3"));
    assert_eq!(second.get(1).unwrap().label, String::from_str(&env, "a4"));
}

#[test]
fn offset_past_the_end_returns_an_empty_page() {
    let (_env, client, querier, target) = setup();
    let page = client.try_get_contract_alerts_paginated(&querier, &target, &100, &10).unwrap().unwrap();
    assert_eq!(page.len(), 0);
}

#[test]
fn zero_limit_returns_an_empty_page() {
    let (_env, client, querier, target) = setup();
    let page = client.try_get_contract_alerts_paginated(&querier, &target, &0, &0).unwrap().unwrap();
    assert_eq!(page.len(), 0);
}

#[test]
fn offset_equal_to_length_returns_an_empty_page() {
    let (_env, client, querier, target) = setup();
    let page = client.try_get_contract_alerts_paginated(&querier, &target, &5, &5).unwrap().unwrap();
    assert_eq!(page.len(), 0);
}

#[test]
fn offset_near_u32_max_does_not_overflow() {
    let (_env, client, querier, target) = setup();
    let page = client.try_get_contract_alerts_paginated(&querier, &target, &u32::MAX, &u32::MAX).unwrap().unwrap();
    assert_eq!(page.len(), 0);
}

/// A limit larger than MAX_BATCH_SIZE is silently clamped: the response contains
/// at most MAX_BATCH_SIZE entries regardless of the requested limit (#209).
#[test]
fn limit_above_max_batch_size_is_clamped() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);

    let querier = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    // Register MAX_BATCH_SIZE + 5 alerts so there is more data than the cap.
    for i in 0..(MAX_BATCH_SIZE + 5) {
        let label = String::from_str(&env, &format!("alert{i}"));
        client.register_alert(
            &owner,
            &target,
            &label,
            &hash64(&env),
            &vec![&env, String::from_str(&env, "rule:transfer")],
            &None,
        );
    }

    // Passing limit = 1000 must be clamped to MAX_BATCH_SIZE.
    let page = client
        .try_get_contract_alerts_paginated(&querier, &target, &0, &1000)
        .unwrap()
        .unwrap();
    assert_eq!(
        page.len(),
        MAX_BATCH_SIZE,
        "limit 1000 should be clamped to MAX_BATCH_SIZE={MAX_BATCH_SIZE}"
    );
}

/// `get_active_alerts_paginated` applies offset/limit *after* filtering inactive alerts, so
/// offset counts active-only results rather than raw index positions (#395).
#[test]
fn active_pagination_offset_counts_active_only_results() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(AlertRegistry, ());
    let client = AlertRegistryClient::new(&env, &contract_id);

    let querier = Address::generate(&env);
    let owner = Address::generate(&env);
    let target = Address::generate(&env);

    // Register 4 alerts, labelled a0..a3 in ID order.
    let labels = ["a0", "a1", "a2", "a3"];
    let mut ids = [0u32; 4];
    for (i, label_str) in labels.iter().enumerate() {
        let label = String::from_str(&env, label_str);
        let id = client.register_alert(
            &owner,
            &target,
            &label,
            &hash64(&env),
            &vec![&env, String::from_str(&env, "rule:transfer")],
            &None,
        );
        ids[i] = id;
    }

    // Deactivate the first 2 alerts (a0, a1), leaving a2 and a3 active.
    client.deactivate_alert(&owner, &ids[0]);
    client.deactivate_alert(&owner, &ids[1]);

    // offset=0, limit=1 must return the 3rd alert (a2), the first active one.
    let first = client
        .try_get_active_alerts_paginated(&querier, &target, &0, &1)
        .unwrap()
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first.get(0).unwrap().label, String::from_str(&env, "a2"));

    // offset=1, limit=10 must return only the 4th alert (a3): offset counts active-only
    // results, not raw index positions.
    let second = client
        .try_get_active_alerts_paginated(&querier, &target, &1, &10)
        .unwrap()
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second.get(0).unwrap().label, String::from_str(&env, "a3"));
}
