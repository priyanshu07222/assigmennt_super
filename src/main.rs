use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Json as AxumJson},
    routing::post,
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use bs58;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_associated_token_account;
use spl_token::{instruction as token_instructions, ID as SPL_TOKEN_PROGRAM};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let server_routes = Router::new()
        .route("/keypair", post(handle_keypair_generation))
        .route("/token/create", post(handle_token_creation))
        .route("/token/mint", post(handle_token_minting))
        .route("/message/sign", post(handle_message_signing))
        .route("/message/verify", post(handle_message_verification))
        .route("/send/sol", post(handle_sol_transfer))
        .route("/send/token", post(handle_token_transfer));

    let tcp_listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("Failed to bind to port 3001");
    
    println!("Solana HTTP server running on http://0.0.0.0:3001");
    axum::serve(tcp_listener, server_routes).await.unwrap();
}

// Input data structures
#[derive(Deserialize)]
struct TokenCreationInput {
    #[serde(rename = "mintAuthority")]
    mint_authority: Option<String>,
    mint: Option<String>,
    decimals: Option<u8>,
}

#[derive(Deserialize)]
struct TokenMintingInput {
    mint: Option<String>,
    destination: Option<String>,
    authority: Option<String>,
    #[serde(deserialize_with = "parse_amount_field")]
    amount: Option<u64>,
}

#[derive(Deserialize)]
struct MessageSigningInput {
    message: Option<String>,
    secret: Option<String>,
}

#[derive(Deserialize)]
struct MessageVerificationInput {
    message: Option<String>,
    signature: Option<String>,
    pubkey: Option<String>,
}

#[derive(Deserialize)]
struct SolTransferInput {
    from: Option<String>,
    to: Option<String>,
    #[serde(deserialize_with = "parse_amount_field")]
    lamports: Option<u64>,
}

#[derive(Deserialize)]
struct TokenTransferInput {
    destination: Option<String>,
    mint: Option<String>,
    owner: Option<String>,
    #[serde(deserialize_with = "parse_amount_field")]
    amount: Option<u64>,
}

// Custom amount parser for flexible input handling
fn parse_amount_field<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct FlexibleAmountVisitor;

    impl<'de> Visitor<'de> for FlexibleAmountVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a number or string representing an amount")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<u64>()
                .map(Some)
                .map_err(|_| de::Error::custom("Invalid amount format"))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(FlexibleAmountVisitor)
}

// Output data structures
#[derive(Serialize)]
struct KeypairOutput {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountMetadata {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionOutput {
    program_id: String,
    accounts: Vec<AccountMetadata>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignatureOutput {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerificationOutput {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SolTransferOutput {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenAccountMetadata {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenTransferOutput {
    program_id: String,
    accounts: Vec<TokenAccountMetadata>,
    instruction_data: String,
}

// Response builders
fn build_success_response<T: Serialize>(data: T) -> (StatusCode, AxumJson<Value>) {
    (StatusCode::OK, AxumJson(json!({
        "success": true,
        "data": data
    })))
}

fn build_error_response(error_message: &str) -> (StatusCode, AxumJson<Value>) {
    (StatusCode::BAD_REQUEST, AxumJson(json!({
        "success": false,
        "error": error_message
    })))
}

// Validation utilities
fn validate_pubkey_format(address_str: &str, field_identifier: &str) -> Result<Pubkey, String> {
    let trimmed_address = address_str.trim();
    
    if trimmed_address.len() < 32 || trimmed_address.len() > 44 {
        return Err(format!("Invalid {} address format", field_identifier));
    }
    
    Pubkey::from_str(trimmed_address)
        .map_err(|_| format!("Invalid {} address", field_identifier))
}

fn validate_amount_bounds(amount_value: u64, field_identifier: &str) -> Result<(), String> {
    if amount_value == 0 {
        return Err(format!("Invalid {} - amount must be greater than 0", field_identifier));
    }
    
    if amount_value > u64::MAX / 2 {
        return Err(format!("Invalid {} - amount too large", field_identifier));
    }
    
    Ok(())
}

fn validate_token_decimals(decimal_count: u8) -> Result<(), String> {
    if decimal_count > 9 {
        return Err("Invalid decimals - maximum allowed is 9".to_string());
    }
    Ok(())
}

fn validate_message_constraints(message_content: &str) -> Result<(), String> {
    if message_content.len() > 1024 {
        return Err("Message too long - maximum 1024 characters".to_string());
    }
    Ok(())
}

// Endpoint implementations
async fn handle_keypair_generation() -> impl IntoResponse {
    let new_keypair = Keypair::new();
    let encoded_secret = bs58::encode(&new_keypair.to_bytes()).into_string();
    let encoded_pubkey = new_keypair.pubkey().to_string();
    
    let keypair_result = KeypairOutput {
        pubkey: encoded_pubkey,
        secret: encoded_secret,
    };
    
    build_success_response(keypair_result)
}

async fn handle_token_creation(Json(input): Json<TokenCreationInput>) -> impl IntoResponse {
    // Extract and validate mint authority
    let authority_address = match input.mint_authority {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate mint address
    let mint_address = match input.mint {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate decimals
    let token_decimals = match input.decimals {
        Some(d) => d,
        None => return build_error_response("Missing required fields"),
    };
    
    // Validate decimals range
    if let Err(error_msg) = validate_token_decimals(token_decimals) {
        return build_error_response(&error_msg);
    }
    
    // Parse and validate addresses
    let parsed_authority = match validate_pubkey_format(authority_address, "mint authority") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    let parsed_mint = match validate_pubkey_format(mint_address, "mint") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    // Security check: prevent self-authorization
    if parsed_authority == parsed_mint {
        return build_error_response("Mint and mint authority cannot be the same");
    }
    
    // Create the token initialization instruction
    let token_instruction = match token_instructions::initialize_mint(
        &SPL_TOKEN_PROGRAM,
        &parsed_mint,
        &parsed_authority,
        None,
        token_decimals,
    ) {
        Ok(instruction) => instruction,
        Err(error) => return build_error_response(&format!("Failed to create token instruction: {}", error)),
    };
    
    // Build account metadata
    let account_list: Vec<AccountMetadata> = token_instruction.accounts
        .iter()
        .map(|account| AccountMetadata {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();
    
    let encoded_instruction_data = general_purpose::STANDARD.encode(&token_instruction.data);
    
    let creation_result = InstructionOutput {
        program_id: token_instruction.program_id.to_string(),
        accounts: account_list,
        instruction_data: encoded_instruction_data,
    };
    
    build_success_response(creation_result)
}

async fn handle_token_minting(Json(input): Json<TokenMintingInput>) -> impl IntoResponse {
    // Extract and validate mint address
    let mint_address = match input.mint {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate destination address
    let destination_address = match input.destination {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate authority address
    let authority_address = match input.authority {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate amount
    let mint_amount = match input.amount {
        Some(amount) => {
            if let Err(error_msg) = validate_amount_bounds(amount, "amount") {
                return build_error_response(&error_msg);
            }
            amount
        },
        None => return build_error_response("Missing required fields"),
    };
    
    // Parse addresses
    let parsed_mint = match validate_pubkey_format(mint_address, "mint") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    let parsed_destination = match validate_pubkey_format(destination_address, "destination") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    let parsed_authority = match validate_pubkey_format(authority_address, "authority") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    // Security check: prevent minting to mint address
    if parsed_destination == parsed_mint {
        return build_error_response("Destination cannot be the same as mint address");
    }
    
    // Create mint-to instruction
    let mint_instruction = match token_instructions::mint_to(
        &SPL_TOKEN_PROGRAM,
        &parsed_mint,
        &parsed_destination,
        &parsed_authority,
        &[],
        mint_amount,
    ) {
        Ok(instruction) => instruction,
        Err(error) => return build_error_response(&format!("Failed to create mint instruction: {}", error)),
    };
    
    // Build account metadata
    let account_list: Vec<AccountMetadata> = mint_instruction.accounts
        .iter()
        .map(|account| AccountMetadata {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
            is_writable: account.is_writable,
        })
        .collect();
    
    let encoded_instruction_data = general_purpose::STANDARD.encode(&mint_instruction.data);
    
    let minting_result = InstructionOutput {
        program_id: mint_instruction.program_id.to_string(),
        accounts: account_list,
        instruction_data: encoded_instruction_data,
    };
    
    build_success_response(minting_result)
}

async fn handle_message_signing(Json(input): Json<MessageSigningInput>) -> impl IntoResponse {
    // Extract and validate message
    let message_content = match input.message {
        Some(ref msg) if !msg.trim().is_empty() => msg.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate secret key
    let secret_key = match input.secret {
        Some(ref key) if !key.trim().is_empty() => key.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Validate message constraints
    if let Err(error_msg) = validate_message_constraints(message_content) {
        return build_error_response(&error_msg);
    }
    
    // Decode secret key
    let secret_bytes = match bs58::decode(secret_key).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return build_error_response("Invalid secret key format"),
    };
    
    // Validate secret key length
    if secret_bytes.len() != 64 {
        return build_error_response("Invalid secret key length");
    }
    
    // Create keypair from secret
    let signing_keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(_) => return build_error_response("Invalid secret key"),
    };
    
    // Sign the message
    let message_signature = signing_keypair.sign_message(message_content.as_bytes());
    let encoded_signature = general_purpose::STANDARD.encode(message_signature.as_ref());
    
    let signing_result = SignatureOutput {
        signature: encoded_signature,
        public_key: signing_keypair.pubkey().to_string(),
        message: message_content.to_string(),
    };
    
    build_success_response(signing_result)
}

async fn handle_message_verification(Json(input): Json<MessageVerificationInput>) -> impl IntoResponse {
    // Extract and validate message
    let message_content = match input.message {
        Some(ref msg) if !msg.trim().is_empty() => msg.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate signature
    let signature_data = match input.signature {
        Some(ref sig) if !sig.trim().is_empty() => sig.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate public key
    let public_key_str = match input.pubkey {
        Some(ref pk) if !pk.trim().is_empty() => pk.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Validate message constraints
    if let Err(error_msg) = validate_message_constraints(message_content) {
        return build_error_response(&error_msg);
    }
    
    // Parse public key
    let verification_pubkey = match validate_pubkey_format(public_key_str, "public key") {
        Ok(pk) => pk,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    // Decode signature
    let signature_bytes = match general_purpose::STANDARD.decode(signature_data) {
        Ok(bytes) => bytes,
        Err(_) => return build_error_response("Invalid signature format"),
    };
    
    // Validate signature length
    if signature_bytes.len() != 64 {
        return build_error_response("Invalid signature length");
    }
    
    // Create signature object
    let decoded_signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return build_error_response("Invalid signature"),
    };
    
    // Verify the signature
    let verification_result = decoded_signature.verify(&verification_pubkey.to_bytes(), message_content.as_bytes());
    
    let verification_output = VerificationOutput {
        valid: verification_result,
        message: message_content.to_string(),
        pubkey: public_key_str.to_string(),
    };
    
    build_success_response(verification_output)
}

async fn handle_sol_transfer(Json(input): Json<SolTransferInput>) -> impl IntoResponse {
    // Extract and validate source address
    let source_address = match input.from {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate destination address
    let destination_address = match input.to {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate lamports amount
    let transfer_lamports = match input.lamports {
        Some(amount) => {
            if let Err(error_msg) = validate_amount_bounds(amount, "lamports") {
                return build_error_response(&error_msg);
            }
            amount
        },
        None => return build_error_response("Missing required fields"),
    };
    
    // Parse addresses
    let parsed_source = match validate_pubkey_format(source_address, "from") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    let parsed_destination = match validate_pubkey_format(destination_address, "to") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    // Security check: prevent self-transfer
    if parsed_source == parsed_destination {
        return build_error_response("Cannot transfer to the same address");
    }
    
    // Create transfer instruction
    let transfer_instruction = system_instruction::transfer(&parsed_source, &parsed_destination, transfer_lamports);
    
    // Build account list
    let account_addresses: Vec<String> = transfer_instruction.accounts
        .iter()
        .map(|account| account.pubkey.to_string())
        .collect();
    
    let encoded_instruction_data = general_purpose::STANDARD.encode(&transfer_instruction.data);
    
    let transfer_result = SolTransferOutput {
        program_id: transfer_instruction.program_id.to_string(),
        accounts: account_addresses,
        instruction_data: encoded_instruction_data,
    };
    
    build_success_response(transfer_result)
}

async fn handle_token_transfer(Json(input): Json<TokenTransferInput>) -> impl IntoResponse {
    // Extract and validate destination address
    let destination_address = match input.destination {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate mint address
    let mint_address = match input.mint {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate owner address
    let owner_address = match input.owner {
        Some(ref addr) if !addr.trim().is_empty() => addr.trim(),
        _ => return build_error_response("Missing required fields"),
    };
    
    // Extract and validate amount
    let transfer_amount = match input.amount {
        Some(amount) => {
            if let Err(error_msg) = validate_amount_bounds(amount, "amount") {
                return build_error_response(&error_msg);
            }
            amount
        },
        None => return build_error_response("Missing required fields"),
    };
    
    // Parse addresses
    let parsed_destination = match validate_pubkey_format(destination_address, "destination") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    let parsed_mint = match validate_pubkey_format(mint_address, "mint") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    let parsed_owner = match validate_pubkey_format(owner_address, "owner") {
        Ok(addr) => addr,
        Err(error_msg) => return build_error_response(&error_msg),
    };
    
    // Get source token account
    let source_token_account = spl_associated_token_account::get_associated_token_address(&parsed_owner, &parsed_mint);
    
    // Security check: prevent self-transfer
    if source_token_account == parsed_destination {
        return build_error_response("Cannot transfer to the same token account");
    }
    
    // Create transfer instruction
    let transfer_instruction = match token_instructions::transfer(
        &SPL_TOKEN_PROGRAM,
        &source_token_account,
        &parsed_destination,
        &parsed_owner,
        &[],
        transfer_amount,
    ) {
        Ok(instruction) => instruction,
        Err(error) => return build_error_response(&format!("Failed to create transfer instruction: {}", error)),
    };
    
    // Build account metadata
    let account_list: Vec<TokenAccountMetadata> = transfer_instruction.accounts
        .iter()
        .map(|account| TokenAccountMetadata {
            pubkey: account.pubkey.to_string(),
            is_signer: account.is_signer,
        })
        .collect();
    
    let encoded_instruction_data = general_purpose::STANDARD.encode(&transfer_instruction.data);
    
    let transfer_result = TokenTransferOutput {
        program_id: transfer_instruction.program_id.to_string(),
        accounts: account_list,
        instruction_data: encoded_instruction_data,
    };
    
    build_success_response(transfer_result)
}