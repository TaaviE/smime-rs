fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn extract_first_multipart_part_raw<'a>(eml_raw: &'a [u8], boundary: &str) -> Result<&'a [u8], String> {
    let body_start = find_bytes(eml_raw, b"\r\n\r\n").map(|p| p + 4).ok_or("Could not locate end of top-level headers (\\r\\n\\r\\n)")?;

    let body = &eml_raw[body_start..];
    let open = format!("--{}\r\n", boundary);
    let close = format!("\r\n--{}", boundary);

    // Opening boundary must be at start of body or preceded by CRLF (RFC 2046)
    let rel = if body.starts_with(open.as_bytes()) {
        0
    } else {
        find_bytes(body, format!("\r\n{}", open).as_bytes())
            .map(|p| p + 2) // skip the leading \r\n
            .ok_or("Opening boundary not found")?
    };
    let part_start = body_start + rel + open.len();

    let part_end =
        find_bytes(&eml_raw[part_start..], close.as_bytes()).map(|p| p + part_start).ok_or("Next boundary after first part not found")?;

    Ok(&eml_raw[part_start..part_end])
}

/// Converts BER-encoded ASN.1 data to strict DER by:
/// - Replacing indefinite-length encodings with definite-length ones
/// - Sorting SET OF elements into canonical (lexicographic) order
pub fn ber_to_der(input: &[u8]) -> Result<Vec<u8>, String> {
    let (der, rest) = ber_tlv_to_der(input)?;
    if !rest.is_empty() {
        return Err(format!("trailing {} bytes after top-level element", rest.len()));
    }
    Ok(der)
}

/// Extract the content portion from a DER-encoded TLV.
fn der_content(tlv: &[u8]) -> Result<&[u8], String> {
    if tlv.is_empty() {
        return Err("empty TLV".to_string());
    }
    let mut pos = 1;
    if tlv[0] & 0x1f == 0x1f {
        while pos < tlv.len() && tlv[pos] & 0x80 != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if pos >= tlv.len() {
        return Err("truncated TLV length".to_string());
    }
    let (len, consumed) = decode_ber_definite_length(tlv[pos], &tlv[pos + 1..])?;
    pos += 1 + consumed;
    if pos + len > tlv.len() {
        return Err("TLV content length exceeds buffer".to_string());
    }
    Ok(&tlv[pos..pos + len])
}

/// Flatten constructed string children into a single primitive encoding.
fn flatten_constructed_string(tag_byte: u8, child_blobs: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    let primitive_tag = tag_byte & !0x20;
    let mut content = Vec::new();
    for blob in &child_blobs {
        content.extend_from_slice(der_content(blob)?);
    }
    let mut out = Vec::new();
    out.push(primitive_tag);
    encode_der_length(&mut out, content.len());
    out.extend_from_slice(&content);
    Ok(out)
}

/// Parse one BER TLV element, returning its DER encoding and the remaining input.
fn ber_tlv_to_der(input: &[u8]) -> Result<(Vec<u8>, &[u8]), String> {
    if input.is_empty() {
        return Err("unexpected end of input".to_string());
    }

    let mut pos = 0;

    // Parse tag
    let tag_start = pos;
    let tag_byte = input[pos];
    pos += 1;
    if tag_byte & 0x1f == 0x1f {
        // Multi-byte tag
        while pos < input.len() && input[pos] & 0x80 != 0 {
            pos += 1;
        }
        if pos >= input.len() {
            return Err("truncated multi-byte tag".to_string());
        }
        pos += 1; // last tag byte
    }
    let tag_bytes = &input[tag_start..pos];
    let is_constructed = tag_byte & 0x20 != 0;

    if pos >= input.len() {
        return Err("truncated length".to_string());
    }

    let len_byte = input[pos];
    pos += 1;

    let is_set = tag_byte == 0x31;
    // BER allows constructed encoding of string types; DER requires primitive.
    let base_tag = tag_byte & !0x20;
    let needs_flatten = is_constructed && matches!(base_tag, 0x03 | 0x04);

    if len_byte == 0x80 {
        // Indefinite length - must be constructed
        if !is_constructed {
            return Err("indefinite length on primitive tag".to_string());
        }
        // Collect children until EOC (0x00 0x00)
        let mut child_blobs: Vec<Vec<u8>> = Vec::new();
        let mut rest = &input[pos..];
        loop {
            if rest.len() >= 2 && rest[0] == 0x00 && rest[1] == 0x00 {
                rest = &rest[2..]; // consume EOC
                break;
            }
            if rest.is_empty() {
                return Err("unterminated indefinite-length element".to_string());
            }
            let (child_der, remaining) = ber_tlv_to_der(rest)?;
            child_blobs.push(child_der);
            rest = remaining;
        }
        if needs_flatten {
            return Ok((flatten_constructed_string(tag_byte, child_blobs)?, rest));
        }
        if is_set {
            child_blobs.sort();
        }
        let children_der: Vec<u8> = child_blobs.into_iter().flatten().collect();
        // Build DER: tag + definite length + children
        let mut out = Vec::new();
        out.extend_from_slice(tag_bytes);
        encode_der_length(&mut out, children_der.len());
        out.extend_from_slice(&children_der);
        Ok((out, rest))
    } else {
        // Definite length
        let (content_len, bytes_consumed) = decode_ber_definite_length(len_byte, &input[pos..])?;
        pos += bytes_consumed;

        if pos + content_len > input.len() {
            return Err(format!("content length {} exceeds available data {} at offset {}", content_len, input.len() - pos, pos));
        }

        if is_constructed {
            // Recursively normalize children
            let content_slice = &input[pos..pos + content_len];
            let mut child_blobs: Vec<Vec<u8>> = Vec::new();
            let mut child_rest = content_slice;
            while !child_rest.is_empty() {
                let (child_der, remaining) = ber_tlv_to_der(child_rest)?;
                child_blobs.push(child_der);
                child_rest = remaining;
            }
            if needs_flatten {
                return Ok((flatten_constructed_string(tag_byte, child_blobs)?, &input[pos + content_len..]));
            }
            if is_set {
                child_blobs.sort();
            }
            let children_der: Vec<u8> = child_blobs.into_iter().flatten().collect();
            let mut out = Vec::new();
            out.extend_from_slice(tag_bytes);
            encode_der_length(&mut out, children_der.len());
            out.extend_from_slice(&children_der);
            Ok((out, &input[pos + content_len..]))
        } else {
            // Primitive - copy as-is (re-encode length for canonical DER)
            let content = &input[pos..pos + content_len];
            let mut out = Vec::new();
            out.extend_from_slice(tag_bytes);
            encode_der_length(&mut out, content_len);
            out.extend_from_slice(content);
            Ok((out, &input[pos + content_len..]))
        }
    }
}

fn decode_ber_definite_length(first: u8, rest: &[u8]) -> Result<(usize, usize), String> {
    if first & 0x80 == 0 {
        Ok((first as usize, 0))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 {
            return Err("zero-length definite long form".to_string());
        }
        if num_bytes > rest.len() {
            return Err("truncated definite length".to_string());
        }
        let mut length: usize = 0;
        for &b in &rest[..num_bytes] {
            length = length.checked_shl(8).ok_or_else(|| "length overflow".to_string())? | b as usize;
        }
        Ok((length, num_bytes))
    }
}

fn encode_der_length(out: &mut Vec<u8>, length: usize) {
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes_needed = (usize::BITS - length.leading_zeros()).div_ceil(8) as usize;
        out.push(0x80 | bytes_needed as u8);
        for i in (0..bytes_needed).rev() {
            out.push((length >> (i * 8)) as u8);
        }
    }
}

struct DerTlv {
    header_len: usize,
    content_len: usize,
    is_constructed: bool,
    tag_byte: u8,
}

/// Parse a DER TLV header at `data[offset..]`, returning header length and content length.
fn parse_der_tlv(data: &[u8], offset: usize) -> Result<DerTlv, String> {
    if offset >= data.len() {
        return Err("unexpected end of input in TLV header".to_string());
    }
    let tag_byte = data[offset];
    let is_constructed = tag_byte & 0x20 != 0;
    let mut pos = offset + 1;
    if tag_byte & 0x1f == 0x1f {
        while pos < data.len() && data[pos] & 0x80 != 0 {
            pos += 1;
        }
        if pos >= data.len() {
            return Err("truncated multi-byte tag".to_string());
        }
        pos += 1;
    }
    if pos >= data.len() {
        return Err("truncated length".to_string());
    }
    let len_byte = data[pos];
    pos += 1;
    let content_len;
    if len_byte & 0x80 == 0 {
        content_len = len_byte as usize;
    } else {
        let num_bytes = (len_byte & 0x7f) as usize;
        if num_bytes == 0 || pos + num_bytes > data.len() {
            return Err("invalid definite length".to_string());
        }
        let mut length: usize = 0;
        for &b in &data[pos..pos + num_bytes] {
            length = length.checked_shl(8).ok_or("length overflow")? | b as usize;
        }
        content_len = length;
        pos += num_bytes;
    }
    Ok(DerTlv { header_len: pos - offset, content_len, is_constructed, tag_byte })
}

/// Sort children of a constructed DER element in place (lexicographic order).
fn sort_children_in_place(data: &mut [u8], offset: usize, header_len: usize, content_len: usize) -> Result<(), String> {
    let content_start = offset + header_len;
    let content_end = content_start + content_len;
    if content_end > data.len() {
        return Err("content exceeds data bounds".to_string());
    }

    // Collect child slices
    let mut children: Vec<Vec<u8>> = Vec::new();
    let mut pos = content_start;
    while pos < content_end {
        let tlv = parse_der_tlv(data, pos)?;
        let child_len = tlv.header_len + tlv.content_len;
        children.push(data[pos..pos + child_len].to_vec());
        pos += child_len;
    }
    if pos != content_end {
        return Err("children don't exactly fill content".to_string());
    }

    children.sort();

    // Write back
    let mut pos = content_start;
    for child in &children {
        data[pos..pos + child.len()].copy_from_slice(child);
        pos += child.len();
    }
    Ok(())
}

/// Navigate CMS ContentInfo -> SignedData and sort implicitly-tagged SET OF fields.
fn sort_cms_implicit_sets(data: &mut [u8]) -> Result<(), String> {
    // ContentInfo is a SEQUENCE
    let ci = parse_der_tlv(data, 0)?;
    if ci.tag_byte != 0x30 || !ci.is_constructed {
        return Err("not a SEQUENCE at top level".to_string());
    }
    let ci_content_start = ci.header_len;

    // First element: OID (content type)
    let oid_tlv = parse_der_tlv(data, ci_content_start)?;
    let after_oid = ci_content_start + oid_tlv.header_len + oid_tlv.content_len;

    // Second element: [0] EXPLICIT (content)
    let explicit0 = parse_der_tlv(data, after_oid)?;
    if explicit0.tag_byte != 0xA0 {
        return Err("expected [0] EXPLICIT after OID".to_string());
    }
    let explicit0_content_start = after_oid + explicit0.header_len;

    // Inside [0] EXPLICIT: SignedData SEQUENCE
    let sd = parse_der_tlv(data, explicit0_content_start)?;
    if sd.tag_byte != 0x30 || !sd.is_constructed {
        return Err("expected SEQUENCE (SignedData) inside [0]".to_string());
    }
    let sd_content_start = explicit0_content_start + sd.header_len;
    let sd_content_end = sd_content_start + sd.content_len;

    // Iterate fields of SignedData
    let mut pos = sd_content_start;
    while pos < sd_content_end {
        let tlv = parse_der_tlv(data, pos)?;
        let elem_total = tlv.header_len + tlv.content_len;

        match tlv.tag_byte {
            // 0xA0 = certificates [0] IMPLICIT SET OF, 0xA1 = crls [1] IMPLICIT SET OF
            0xA0 | 0xA1 if tlv.is_constructed => {
                sort_children_in_place(data, pos, tlv.header_len, tlv.content_len)?;
            }
            // 0x31 = SET OF (signerInfos or digestAlgorithms)
            // For signerInfos, we need to look inside each SignerInfo for implicit SET OF
            0x31 if tlv.is_constructed => {
                sort_signer_infos_implicit_sets(data, pos + tlv.header_len, tlv.content_len)?;
            }
            _ => {}
        }

        pos += elem_total;
    }
    Ok(())
}

/// Within a SET OF SignerInfos content region, iterate each SignerInfo SEQUENCE
/// and sort any implicit SET OF fields (0xA0/0xA1) within it.
fn sort_signer_infos_implicit_sets(data: &mut [u8], content_start: usize, content_len: usize) -> Result<(), String> {
    let content_end = content_start + content_len;
    let mut si_pos = content_start;
    while si_pos < content_end {
        let si_tlv = parse_der_tlv(data, si_pos)?;
        // Each SignerInfo is a SEQUENCE
        if si_tlv.tag_byte == 0x30 && si_tlv.is_constructed {
            let si_content_start = si_pos + si_tlv.header_len;
            let si_content_end = si_content_start + si_tlv.content_len;
            let mut field_pos = si_content_start;
            while field_pos < si_content_end {
                let field_tlv = parse_der_tlv(data, field_pos)?;
                if (field_tlv.tag_byte == 0xA0 || field_tlv.tag_byte == 0xA1) && field_tlv.is_constructed {
                    sort_children_in_place(data, field_pos, field_tlv.header_len, field_tlv.content_len)?;
                }
                field_pos += field_tlv.header_len + field_tlv.content_len;
            }
        }
        si_pos += si_tlv.header_len + si_tlv.content_len;
    }
    Ok(())
}

/// Converts unnecessarily BER-encoded CMS/PKCS#7 data to DER
pub fn ber_to_der_cms(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut der = ber_to_der(input)?;
    sort_cms_implicit_sets(&mut der)?;
    Ok(der)
}

pub fn truncate_middle(s: &str, max_len: usize) -> String {
    if max_len < 4 || s.len() <= max_len {
        return s.to_string();
    }
    let keep = (max_len - 3) / 2;
    // Find char-boundary-safe indices to avoid panicking on multi-byte UTF-8
    let start_end = s.char_indices().map(|(i, _)| i).take_while(|&i| i <= keep).last().unwrap_or(0);
    let suffix_start = s.char_indices().rev().map(|(i, _)| i).take_while(|&i| s.len() - i <= keep).last().unwrap_or(s.len());
    format!("{}...{}", &s[..start_end], &s[suffix_start..])
}

pub fn email_domain_to_a_label(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        // RFC 9598: 5. Convert all U-labels to A-labels
        if let Ok(ascii_domain) = idna::domain_to_ascii(domain) {
            return format!("{}@{}", local, ascii_domain);
        }
    }
    email.to_string()
}

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
