pub struct CertificateSigningRequest {
    
}

pub fn generate_csr<
    SK: Signer + HasPublicKey + HasByteSource + HasAlgorithmIdentifier,
    BPK: HasByteSource + HasAlgorithmIdentifier,
>(
    issuer_key: &SK,
    subject_key: Option<&BPK>,
    issuer_cn: &str,
    subject_cn: Option<&str>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    is_ca: bool,
    //subject_alternative_names: Option<&[&str]>,
) -> Result<CertificateSigningRequest, ClientError> {