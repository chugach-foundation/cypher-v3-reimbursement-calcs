use anchor_lang::{prelude::Pubkey, AccountDeserialize, Discriminator};
use anchor_spl::token::TokenAccount;
use cypher_client::{
    utils::{adjust_decimals, derive_account_address},
    CypherAccount, CypherSubAccount, OracleProducts,
};
use cypher_utils::{
    contexts::{AccountContext, CacheContext, CypherContext, SubAccountContext},
    utils::{
        get_multiple_cypher_program_accounts, get_multiple_cypher_zero_copy_accounts,
        get_program_accounts_without_data,
    },
};
use fixed::{traits::ToFixed, types::I80F48};
use lip_client::{utils::derive_deposit_authority, Deposit};
use pyth_sdk_solana::state::{load_price_account, load_product_account};
use solana_client::{
    client_error::ClientError,
    nonblocking::rpc_client::RpcClient,
    rpc_filter::{Memcmp, MemcmpEncodedBytes, RpcFilterType},
};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    ops::Div,
    str::{from_utf8, FromStr},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use switchboard_v2::AggregatorAccountData;

pub const RPC_URL: &str = "https://cypher.rpcpool.com/e82dcf8c7f2de737f6b9fecf14a5";

struct AccountData {
    pub cypher_account: Pubkey,
    pub owner: Pubkey,
    pub amounts: [u64; 16],
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountDataJson {
    pub cypher_account: String,
    pub owner: String,
    pub amounts: Vec<(String, f64)>,
}

fn format_account_data(account: &AccountData) -> String {
    format!(
        "{},{},{}\n",
        account.cypher_account,
        account.owner,
        account
            .amounts
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn format_package_header(tokens: &[TokenInfo]) -> String {
    format!(
        "account,owner,{}\n",
        tokens
            .iter()
            .map(|t| t.symbol.to_string())
            .collect::<Vec<String>>()
            .join(",")
    )
}

fn write_csv_row(file: &mut File, row: &str) {
    write!(file, "{}", row).unwrap();
}

fn write_csv_header(file: &mut File, header: &str) {
    write!(file, "{}", header).unwrap();
}

struct TokenInfo {
    pub symbol: String,
    pub decimals: i32,
    pub available_native: u64,
    pub reimbursement_price: I80F48,
}

#[tokio::main]
async fn main() {
    let rpc_client = Arc::new(RpcClient::new(RPC_URL.to_string()));

    let cypher_ctx = CypherContext::load(&rpc_client).await.unwrap();
    let cache_ctx = CacheContext::load(&rpc_client).await.unwrap();

    let pools = cypher_ctx.pools.read().await;
    let oracle_products_pubkeys = cache_ctx
        .state
        .caches
        .iter()
        .filter(|c| c.oracle_products != Pubkey::default())
        .map(|c| c.oracle_products)
        .collect::<Vec<Pubkey>>();

    let oracle_products_accounts = get_multiple_cypher_program_accounts::<OracleProducts>(
        &rpc_client,
        &oracle_products_pubkeys,
    )
    .await
    .unwrap();

    let mut token_infos: Vec<TokenInfo> = Vec::new();
    let mut total_amount = I80F48::ZERO;

    for pool in pools.iter() {
        let symbol = from_utf8(&pool.state.pool_name)
            .unwrap()
            .trim_matches(char::from(0))
            .to_string();
        let pool_node = pool.pool_nodes.first().unwrap();
        let pool_node_vault_data = rpc_client
            .get_account_data(&pool_node.state.token_vault)
            .await
            .unwrap();
        let pool_node_vault =
            TokenAccount::try_deserialize(&mut pool_node_vault_data.as_slice()).unwrap();
        let oracle_products = oracle_products_accounts
            .iter()
            .find(|o| o.token_mint == pool.state.token_mint)
            .unwrap();
        let reimbursement_price = match oracle_products.products_type {
            cypher_client::ProductsType::Pyth => {
                let prod_account_pubkey =
                    Pubkey::try_from(oracle_products.products.first().unwrap().to_vec()).unwrap();
                let prod_account_data = rpc_client
                    .get_account_data(&prod_account_pubkey)
                    .await
                    .unwrap();
                let prod_account = load_product_account(&prod_account_data).unwrap();

                let price_feed_account_data = rpc_client
                    .get_account_data(&prod_account.px_acc)
                    .await
                    .unwrap();
                let price_feed_account = load_price_account(&price_feed_account_data).unwrap();

                let price = I80F48::from_num(price_feed_account.agg.price)
                    .checked_div(I80F48::from_num(
                        10u64.pow(price_feed_account.expo.abs() as u32),
                    ))
                    .unwrap();

                price
            }
            cypher_client::ProductsType::Switchboard => {
                let aggregator_account_pubkey =
                    Pubkey::try_from(oracle_products.products.first().unwrap().to_vec()).unwrap();
                let aggregator_account_data = rpc_client
                    .get_account_data(&aggregator_account_pubkey)
                    .await
                    .unwrap();
                let aggregator_account =
                    AggregatorAccountData::new_from_bytes(&aggregator_account_data).unwrap();

                let result: f64 = aggregator_account.get_result().unwrap().try_into().unwrap();

                I80F48::from_num(result)
            }
            _ => I80F48::ZERO,
        };

        let available = adjust_decimals(
            I80F48::from(pool_node_vault.amount),
            pool.state.config.decimals,
        );
        let pool_value = available.checked_mul(reimbursement_price).unwrap();

        total_amount += pool_value;

        println!(
            "{} Reimbursement Price: {} - Value: {}",
            symbol, reimbursement_price, pool_value
        );

        token_infos.push(TokenInfo {
            symbol,
            decimals: pool.state.config.decimals.into(),
            available_native: pool_node_vault.amount,
            reimbursement_price,
        });
    }

    let cypher_accounts = get_all_cypher_accounts(&rpc_client).await.unwrap();
    println!("Fetched {} Accounts.", cypher_accounts.len());

    let cypher_sub_accounts = get_all_cypher_sub_accounts(&rpc_client).await.unwrap();
    println!("Fetched {} Sub Accounts.", cypher_sub_accounts.len());

    let lip_deposits = get_all_lip_deposits(&rpc_client).await.unwrap();
    println!("Fetched {} LIP Deposits.", lip_deposits.len());

    let mut accounts_equity_info = Vec::new();

    for account in cypher_accounts.iter() {
        let sub_account_pubkeys = account
            .state
            .sub_account_caches
            .iter()
            .filter(|sac| sac.sub_account != Pubkey::default())
            .map(|sac| sac.sub_account)
            .collect::<Vec<Pubkey>>();
        let sub_accounts = cypher_sub_accounts
            .iter()
            .filter(|sa| sub_account_pubkeys.contains(&sa.address))
            .collect::<Vec<&SubAccountContext>>();

        let account_equity_info =
            get_account_equity(&cypher_ctx, &cache_ctx, account, &sub_accounts).await;

        // println!(
        //     "Account: {} - Equity: {:?}",
        //     account.address, account_equity_info
        // );
        if account_equity_info.equity > 0.0 {
            accounts_equity_info.push(account_equity_info);
        }
    }

    let mut wallet_equity_infos: Vec<WalletEquityInfo> = Vec::new();

    let mut lip_deposit_owners = lip_deposits
        .iter()
        .map(|(_, d)| d.owner)
        .map(|p| p.to_string())
        .collect::<Vec<String>>();
    lip_deposit_owners.sort_unstable();
    lip_deposit_owners.dedup();

    let mut owner_to_account_map: HashMap<String, Vec<AccountEquityInfo>> = HashMap::new();

    for account in accounts_equity_info.iter() {
        // check if this account belongs to lip
        if let Some((_, d, _)) = lip_deposits
            .iter()
            .map(|(p, d)| {
                let deposit_authority = derive_deposit_authority(p).0;
                let cypher_account = derive_account_address(&deposit_authority, 0).0;
                (p, d, cypher_account)
            })
            .find(|(_, _, ca)| ca.to_string() == account.address)
        {
            // get the owner
            let owner = d.owner.to_string();

            // if this owner is not in the map, add it
            if !owner_to_account_map.contains_key(&owner) {
                owner_to_account_map.insert(d.owner.to_string(), vec![account.clone()]);
                continue;
            }

            // if we get here we know the owner is already in the map
            // so let's fetch the value for the key
            if let Some(accounts) = owner_to_account_map.get_mut(&owner) {
                accounts.push(account.clone());
                continue;
            }
        }
        // get the owner
        let owner = account.owner.clone();

        // if this owner is not in the map, add it
        if !owner_to_account_map.contains_key(&owner) {
            owner_to_account_map.insert(owner.to_string(), vec![account.clone()]);
            continue;
        }

        // if we get here we know the owner is already in the map
        // so let's fetch the value for the key
        if let Some(accounts) = owner_to_account_map.get_mut(&owner) {
            accounts.push(account.clone());
            continue;
        }
    }

    for (key, value) in owner_to_account_map.iter() {
        let equity = value.iter().map(|a| a.equity).sum();
        let first_account_found = value.first().unwrap();

        wallet_equity_infos.push(WalletEquityInfo {
            address: key.clone(),
            account: first_account_found.address.clone(),
            equity,
            account_equity_infos: value.clone(),
        });
    }

    accounts_equity_info.sort_by(|a, b| a.equity.partial_cmp(&b.equity).unwrap());
    wallet_equity_infos.sort_by(|a, b| a.equity.partial_cmp(&b.equity).unwrap());

    let total_equity = I80F48::from_num::<f64>(
        wallet_equity_infos
            .iter()
            .filter(|a| a.equity > 0.0)
            .map(|a| a.equity)
            .sum(),
    );

    let mut total_reimbursement_value = I80F48::ZERO;

    let mut packages: Vec<AccountData> = Vec::new();
    let mut token_totals_native = [0u64; 16];

    for wallet_equity in wallet_equity_infos.iter() {
        let mut package = [0u64; 16];

        let total_share = I80F48::from_num(wallet_equity.equity)
            .checked_div(total_equity)
            .unwrap();
        let reimbursement_value = total_amount.checked_mul(total_share).unwrap();
        total_reimbursement_value += reimbursement_value;

        println!("---------------------------------------------------------------------------------------");
        println!(
            "Account: {} - Equity: {} - Total Share {} - Reimbursement Value: {}",
            wallet_equity.address, wallet_equity.equity, total_share, reimbursement_value
        );

        for (idx, token) in token_infos.iter().enumerate() {
            let available =
                adjust_decimals(I80F48::from(token.available_native), token.decimals as u8);
            let pool_value = available.checked_mul(token.reimbursement_price).unwrap();
            let pool_share = pool_value.checked_div(total_amount).unwrap();

            let token_reimbursement_amount = reimbursement_value
                .checked_mul(pool_share)
                .and_then(|n| n.checked_div(token.reimbursement_price))
                .unwrap();
            let token_reimbursement_amount_native = token_reimbursement_amount
                .checked_mul(I80F48::from(10u64.pow(token.decimals as u32)))
                .unwrap()
                .floor()
                .to_num();
            println!(
                "Token: {} - Available: {} - Reimbursement: {} - Native: {}",
                token.symbol,
                token.available_native,
                token_reimbursement_amount,
                token_reimbursement_amount_native
            );
            package[idx] = token_reimbursement_amount_native;
            token_totals_native[idx] += token_reimbursement_amount_native;
        }
        packages.push(AccountData {
            owner: Pubkey::from_str(&wallet_equity.address).unwrap(),
            cypher_account: Pubkey::from_str(&wallet_equity.account).unwrap(),
            amounts: package,
        });
        println!("---------------------------------------------------------------------------------------");
    }

    println!("-----------------------------------------------");
    for (idx, token) in token_infos.iter().enumerate() {
        println!(
            "Token: {} - Available: {} - Total Reimbursement: {}",
            token.symbol,
            adjust_decimals(I80F48::from(token.available_native), token.decimals as u8),
            adjust_decimals(I80F48::from(token_totals_native[idx]), token.decimals as u8)
        );
    }
    println!("-----------------------------------------------");

    println!("Total Amount Available: {}", total_amount);
    println!("Total Equity (Unweighted): {}", total_equity);
    println!("Total Reimbursement Value: {}", total_reimbursement_value);
    println!(
        "Socalized Loss: {}",
        total_amount.checked_div(total_equity).unwrap()
    );

    let cur_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    // produce account equities snapshot as json with all of the account and sub account data
    let account_equities_file_path = format!("account_equities_{}.json", cur_ts.as_millis());
    let account_equities_data = serde_json::to_vec(&accounts_equity_info).unwrap();
    let mut account_equities_file = File::create(account_equities_file_path).unwrap();
    account_equities_file
        .write_all(&account_equities_data)
        .unwrap();

    // produce wallet equities snapshot as json where accounts are merged for the wallet
    let wallet_equities_file_path = format!("wallet_equities_{}.json", cur_ts.as_millis());
    let wallet_equities_data = serde_json::to_vec(&wallet_equity_infos).unwrap();
    let mut wallet_equities_file = File::create(wallet_equities_file_path).unwrap();
    wallet_equities_file
        .write_all(&wallet_equities_data)
        .unwrap();

    // produce account reimbursement packages as csv with token amounts for each available token in native units
    let packages_json = packages
        .iter()
        .map(|p| AccountDataJson {
            cypher_account: p.cypher_account.to_string(),
            owner: p.owner.to_string(),
            amounts: p
                .amounts
                .iter()
                .enumerate()
                .map(|(idx, amount)| {
                    if idx > token_infos.len() - 1 {
                        (String::new(), *amount as f64)
                    } else {
                        (
                            token_infos[idx].symbol.clone(),
                            (*amount as f64)
                                .div(10u64.pow(token_infos[idx].decimals as u32) as f64),
                        )
                    }
                })
                .collect(),
        })
        .collect::<Vec<AccountDataJson>>();
    let account_packages_json_file_path = format!("account_packages_{}.json", cur_ts.as_secs());
    let account_packages_data = serde_json::to_vec(&packages_json).unwrap();
    let mut account_packages_json_file = File::create(account_packages_json_file_path).unwrap();
    account_packages_json_file
        .write_all(&account_packages_data)
        .unwrap();

    // produce account reimbursement packages as csv with token amounts for each available token in native units
    let account_packages_file_path = format!("account_packages_{}.csv", cur_ts.as_secs());
    let mut account_packages_file = File::create(account_packages_file_path).unwrap();
    write_csv_header(
        &mut account_packages_file,
        &format_package_header(&token_infos),
    );

    for package in packages.iter() {
        write_csv_row(&mut account_packages_file, &format_account_data(package));
    }
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SerumOrdersInfo {
    pub market: String,
    pub base_quantity_free: f64,
    pub quote_quantity_free: f64,
    pub bid_base_quantity: f64,
    pub bid_quote_quantity: f64,
    pub ask_base_quantity: f64,
    pub ask_quote_quantity: f64,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletEquityInfo {
    pub address: String,
    pub account: String,
    pub equity: f64,
    pub account_equity_infos: Vec<AccountEquityInfo>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountEquityInfo {
    pub address: String,
    pub owner: String,
    pub assets_value_weighted: f64,
    pub assets_value_unweighted: f64,
    pub liabilities_value_weighted: f64,
    pub liabilities_value_unweighted: f64,
    pub equity: f64,
    pub sub_account_equity_infos: Vec<SubAccountEquityInfo>,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenPosition {
    pub symbol: String,
    pub mint: String,
    pub amount: f64,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct DerivativePosition {
    pub symbol: String,
    pub market: String,
    pub side: String,
    pub amount: f64,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubAccountEquityInfo {
    pub address: String,
    pub assets_value_weighted: f64,
    pub assets_value_unweighted: f64,
    pub liabilities_value_weighted: f64,
    pub liabilities_value_unweighted: f64,
    pub equity: f64,
    pub spot_positions: Vec<TokenPosition>,
    pub derivative_positions: Vec<DerivativePosition>,
}

async fn get_account_equity(
    cypher_context: &CypherContext,
    cache_context: &CacheContext,
    account: &AccountContext,
    sub_accounts: &[&SubAccountContext],
) -> AccountEquityInfo {
    let pools = cypher_context.pools.read().await;
    let perp_markets = cypher_context.perp_markets.read().await;
    let futures_markets = cypher_context.futures_markets.read().await;
    let mut account_assets_value_weighted = I80F48::ZERO;
    let mut account_assets_value_unweighted = I80F48::ZERO;
    let mut account_liabilities_value_weighted = I80F48::ZERO;
    let mut account_liabilities_value_unweighted = I80F48::ZERO;
    let mut account_equity = I80F48::ZERO;

    let mut sub_account_equity_infos = Vec::new();

    for sub_account in sub_accounts.iter() {
        let (assets_value_weighted, assets_value_unweighted) = sub_account.state.get_assets_value(
            &cache_context.state,
            cypher_client::MarginCollateralRatioType::Initialization,
        );
        account_assets_value_weighted += assets_value_weighted;
        account_assets_value_unweighted += assets_value_unweighted;

        let (liabilities_value_weighted, liabilities_value_unweighted) =
            sub_account.state.get_liabilities_value(
                &cache_context.state,
                cypher_client::MarginCollateralRatioType::Initialization,
            );
        account_liabilities_value_weighted += liabilities_value_weighted;
        account_liabilities_value_unweighted += liabilities_value_unweighted;

        let sub_account_equity = assets_value_unweighted - liabilities_value_unweighted;
        account_equity += sub_account_equity;

        let spot_positions = sub_account.state.get_spot_positions();
        let derivative_positions = sub_account.state.get_derivative_positions();

        sub_account_equity_infos.push(SubAccountEquityInfo {
            address: sub_account.address.to_string(),
            assets_value_weighted: assets_value_weighted.to_num(),
            assets_value_unweighted: assets_value_unweighted.to_num(),
            liabilities_value_weighted: liabilities_value_weighted.to_num(),
            liabilities_value_unweighted: liabilities_value_unweighted.to_num(),
            equity: sub_account_equity.to_num(),
            spot_positions: spot_positions
                .iter()
                .map(|sp| {
                    let cache = cache_context.state.get_price_cache(sp.cache_index.into());
                    let pool = pools
                        .iter()
                        .find(|p| p.state.token_mint == sp.token_mint)
                        .unwrap();
                    let pool_name = from_utf8(&pool.state.pool_name)
                        .unwrap()
                        .trim_matches(char::from(0));
                    TokenPosition {
                        symbol: pool_name.to_string(),
                        mint: sp.token_mint.to_string(),
                        amount: adjust_decimals(sp.total_position(cache), cache.decimals).to_num(),
                    }
                })
                .collect(),
            derivative_positions: derivative_positions
                .iter()
                .map(|dp| {
                    let cache = cache_context.state.get_price_cache(dp.cache_index.into());
                    let market_name = match dp.market_type {
                        cypher_client::MarketType::PerpetualFuture => {
                            let perp_market = perp_markets
                                .iter()
                                .find(|p| p.address == dp.market)
                                .unwrap();
                            let market_name = from_utf8(&perp_market.state.inner.market_name)
                                .unwrap()
                                .trim_matches(char::from(0));
                            market_name.to_string()
                        }
                        _ => {
                            let futures_market = futures_markets
                                .iter()
                                .find(|p| p.address == dp.market)
                                .unwrap();
                            let market_name = from_utf8(&futures_market.state.inner.market_name)
                                .unwrap()
                                .trim_matches(char::from(0));
                            market_name.to_string()
                        }
                    };
                    let side = if dp.total_position().is_positive() {
                        "Long".to_string()
                    } else {
                        "Short".to_string()
                    };
                    DerivativePosition {
                        symbol: market_name,
                        market: dp.market.to_string(),
                        side,
                        amount: adjust_decimals(dp.total_position(), cache.perp_decimals).to_num(),
                    }
                })
                .collect(),
        })
    }

    AccountEquityInfo {
        address: account.address.to_string(),
        owner: account.state.authority.to_string(),
        assets_value_weighted: account_assets_value_weighted.to_num(),
        assets_value_unweighted: account_assets_value_unweighted.to_num(),
        liabilities_value_weighted: account_liabilities_value_weighted.to_num(),
        liabilities_value_unweighted: account_liabilities_value_unweighted.to_num(),
        equity: account_equity.to_num(),
        sub_account_equity_infos,
    }
}

#[allow(deprecated)]
async fn get_all_lip_deposits(
    rpc_client: &Arc<RpcClient>,
) -> Result<Vec<(Pubkey, Box<Deposit>)>, ClientError> {
    let mut deposits = Vec::new();

    let deposit_account_disc = Deposit::discriminator();
    let filters = vec![RpcFilterType::Memcmp(Memcmp {
        offset: 0,
        bytes: MemcmpEncodedBytes::Bytes(deposit_account_disc.to_vec()),
        encoding: None,
    })];

    let all_accounts = get_program_accounts_without_data(&rpc_client, filters, &lip_client::id())
        .await
        .unwrap();
    println!("Fetched {} program accounts.", all_accounts.len());

    for i in (0..all_accounts.len()).step_by(100) {
        let mut pubkeys = Vec::new();
        pubkeys.extend(
            all_accounts[i..all_accounts.len().min(i + 100)]
                .iter()
                .map(|a| a.0),
        );
        //println!("Fetching Accounts: {:?}", pubkeys);

        let res = get_multiple_cypher_program_accounts::<Deposit>(&rpc_client, &pubkeys)
            .await
            .unwrap()
            .iter()
            .enumerate()
            .map(|(idx, oo)| (pubkeys[idx], oo.to_owned()))
            .collect::<Vec<(Pubkey, Box<Deposit>)>>();
        //println!("Fetched {} Accounts.", res.len());

        deposits.extend(res);
    }

    Ok(deposits)
}

#[allow(deprecated)]
async fn get_all_cypher_accounts(
    rpc_client: &Arc<RpcClient>,
) -> Result<Vec<AccountContext>, ClientError> {
    let mut sub_accounts = Vec::new();

    let cypher_account_disc = CypherAccount::discriminator();
    let filters = vec![RpcFilterType::Memcmp(Memcmp {
        offset: 0,
        bytes: MemcmpEncodedBytes::Bytes(cypher_account_disc.to_vec()),
        encoding: None,
    })];

    let all_accounts =
        get_program_accounts_without_data(&rpc_client, filters, &cypher_client::id())
            .await
            .unwrap();
    println!("Fetched {} program accounts.", all_accounts.len());

    for i in (0..all_accounts.len()).step_by(100) {
        let mut pubkeys = Vec::new();
        pubkeys.extend(
            all_accounts[i..all_accounts.len().min(i + 100)]
                .iter()
                .map(|a| a.0),
        );
        //println!("Fetching Accounts: {:?}", pubkeys);

        let res = get_multiple_cypher_zero_copy_accounts::<CypherAccount>(&rpc_client, &pubkeys)
            .await
            .unwrap();
        //println!("Fetched {} Accounts.", res.len());

        for (idx, account) in res.iter().enumerate() {
            let ctx = AccountContext::new(pubkeys[idx], account.clone());
            sub_accounts.push(ctx);
        }
    }

    Ok(sub_accounts)
}

#[allow(deprecated)]
async fn get_all_cypher_sub_accounts(
    rpc_client: &Arc<RpcClient>,
) -> Result<Vec<SubAccountContext>, ClientError> {
    let mut sub_accounts = Vec::new();

    let cypher_sub_account_disc = CypherSubAccount::discriminator();
    let filters = vec![RpcFilterType::Memcmp(Memcmp {
        offset: 0,
        bytes: MemcmpEncodedBytes::Bytes(cypher_sub_account_disc.to_vec()),
        encoding: None,
    })];

    let all_sub_accounts =
        get_program_accounts_without_data(&rpc_client, filters, &cypher_client::id())
            .await
            .unwrap();
    println!("Fetched {} program accounts.", all_sub_accounts.len());

    for i in (0..all_sub_accounts.len()).step_by(100) {
        let mut pubkeys = Vec::new();
        pubkeys.extend(
            all_sub_accounts[i..all_sub_accounts.len().min(i + 100)]
                .iter()
                .map(|a| a.0),
        );
        //println!("Fetching Sub Accounts: {:?}", pubkeys);

        let res = get_multiple_cypher_zero_copy_accounts::<CypherSubAccount>(&rpc_client, &pubkeys)
            .await
            .unwrap();
        //println!("Fetched {} Sub Accounts.", res.len());

        for (idx, sub_account) in res.iter().enumerate() {
            let ctx = SubAccountContext::new(pubkeys[idx], sub_account.clone());
            sub_accounts.push(ctx);
        }
    }

    Ok(sub_accounts)
}
