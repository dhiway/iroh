//! Support for handling DNS resource records for dialing by [`EndpointId`].
//!
//! Dialing by [`EndpointId`] is supported by iroh endpoints publishing [Pkarr] records to DNS
//! servers or the Mainline DHT.  This module supports creating and parsing these records.
//!
//! [`EndpointInfo`] combines an [`iroh_base::EndpointId`] with [`EndpointData`]:
//! the addressing and metadata that discovery services publish and resolve.
//! Discovery services use [`AddrFilter`] to control which addresses are published.
//!
//! This module also provides serialization to and from pkarr signed packets and
//! DNS TXT records.
//!
//! DNS records are published under the following names:
//!
//! `_iroh.<z32-endpoint-id>.<origin-domain> TXT`
//!
//! - `_iroh` is the record name as defined by [`IROH_TXT_NAME`].
//!
//! - `<z32-endpoint-id>` is the [z-base-32] encoding of the [`EndpointId`].
//!
//! - `<origin-domain>` is the domain name of the publishing DNS server,
//!   [`N0_DNS_ENDPOINT_ORIGIN_PROD`] is the server operated by number0 for production.
//!   [`N0_DNS_ENDPOINT_ORIGIN_STAGING`] is the server operated by number0 for testing.
//!
//! - `TXT` is the DNS record type.
//!
//! The returned TXT records must contain a string value of the form `key=value` as defined
//! in [RFC1464].  The following attributes are defined:
//!
//! - `relay=<url>`: The home [`RelayUrl`] of this endpoint.
//!
//! - `addr=<addr> <addr>`: A space-separated list of sockets addresses for this iroh endpoint.
//!   Each address is an IPv4 or IPv6 address with a port.
//!
//! [Pkarr]: https://app.pkarr.org
//! [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
//! [RFC1464]: https://www.rfc-editor.org/rfc/rfc1464
//! [`RelayUrl`]: iroh_base::RelayUrl
//! [`IROH_TXT_NAME`]: crate::IROH_TXT_NAME
//! [`N0_DNS_ENDPOINT_ORIGIN_PROD`]: crate::dns::N0_DNS_ENDPOINT_ORIGIN_PROD
//! [`N0_DNS_ENDPOINT_ORIGIN_STAGING`]: crate::dns::N0_DNS_ENDPOINT_ORIGIN_STAGING

use std::{
    borrow::Cow,
    collections::{BTreeSet, HashSet},
    fmt::{self, Display},
    hash::Hash,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr};
use n0_error::{ensure, stack_error};
use url::Url;

use crate::{
    attrs::{CMNS_TXT_NAME, EncodingError, IROH_TXT_NAME, IrohAttr, ParseError, TxtAttrs},
    pkarr,
};

/// Data about an endpoint that may be published to and resolved from discovery services.
///
/// This includes an optional [`RelayUrl`], a set of direct addresses, and the optional
/// [`UserData`], a string that can be set by applications and is not parsed or used by iroh
/// itself.
///
/// This struct does not include the endpoint's [`EndpointId`], only the data *about* a certain
/// endpoint. See [`EndpointInfo`] for a struct that contains a [`EndpointId`] with associated [`EndpointData`].
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EndpointData {
    /// addresses where this endpoint can be reached.
    addrs: Vec<TransportAddr>,
    /// Optional user-defined [`UserData`] for this endpoint.
    user_data: Option<UserData>,
}

fn dedup<T: Eq + Hash + Clone>(items: &mut Vec<T>) -> HashSet<T> {
    // Remove all duplicate entries, but keep the array order.
    let mut seen = HashSet::new();
    items.retain(|item| seen.insert(item.clone()));
    seen
}

impl EndpointData {
    /// Creates a new [`EndpointData`] with given list of transport addresses.
    ///
    /// The address order is preserved, so it can encode priority for address lookup
    /// services, should they not fit into e.g. a single DNS packet otherwise.
    ///
    /// If the addresses contain duplicate entries, those entries are removed.
    pub fn new(mut addrs: Vec<TransportAddr>) -> Self {
        dedup(&mut addrs);
        Self {
            addrs,
            user_data: None,
        }
    }

    /// Sets the user-defined data and returns the updated endpoint info.
    ///
    /// Useful for calling on construction after [`EndpointData::new`] or [`EndpointData::from_iter`].
    ///
    /// See also [`Self::set_user_data`].
    pub fn with_user_data(mut self, user_data: UserData) -> Self {
        self.user_data = Some(user_data);
        self
    }

    /// Adds the relay URL to the end of the endpoint data, unless it already existed.
    pub fn add_relay_url(&mut self, relay_url: RelayUrl) {
        let addr = TransportAddr::Relay(relay_url);
        if !self.addrs.contains(&addr) {
            self.addrs.push(addr);
        }
    }

    /// Adds addresses in order with duplicates or already existing addresses filtered out.
    pub fn add_ip_addrs(&mut self, addresses: Vec<SocketAddr>) {
        self.add_addrs(addresses.into_iter().map(TransportAddr::Ip))
    }

    /// Adds addresses to the endpoint data in the given order, but with duplicates filtered.
    pub fn add_addrs(&mut self, addrs: impl IntoIterator<Item = TransportAddr>) {
        let mut addr_set = dedup(&mut self.addrs);
        for addr in addrs.into_iter() {
            if !addr_set.contains(&addr) {
                self.addrs.push(addr.clone());
                addr_set.insert(addr);
            }
        }
    }

    /// Sets the user-defined data.
    pub fn set_user_data(&mut self, user_data: Option<UserData>) {
        self.user_data = user_data;
    }

    /// Removes all direct addresses from the endpoint data.
    pub fn clear_ip_addrs(&mut self) {
        self.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));
    }

    /// Removes all relay URLs from the endpoint data.
    pub fn clear_relay_urls(&mut self) {
        self.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Relay(_)));
    }

    /// Returns the relay URL of the endpoint.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Relay(url) => Some(url),
            _ => None,
        })
    }

    /// Returns the optional user-defined data of the endpoint.
    pub fn user_data(&self) -> Option<&UserData> {
        self.user_data.as_ref()
    }

    /// Returns the direct addresses of the endpoint.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Ip(addr) => Some(addr),
            _ => None,
        })
    }

    /// Returns the full list of all known addresses.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddr> {
        self.addrs.iter()
    }

    /// Returns whether this has any addresses.
    pub fn has_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    /// Apply the given filter to the current addresses.
    ///
    /// Returns a vec to allow re-ordering of addresses.
    pub fn filtered_addrs(&self, filter: &AddrFilter) -> Cow<'_, Vec<TransportAddr>> {
        filter.apply(&self.addrs)
    }

    /// Returns the `EndpointData` with given filter applied.
    pub fn apply_filter(&self, filter: &AddrFilter) -> Cow<'_, Self> {
        match self.filtered_addrs(filter) {
            Cow::Borrowed(_) => Cow::Borrowed(self),
            Cow::Owned(addrs) => {
                let mut data = EndpointData::new(addrs);
                data.set_user_data(self.user_data.clone());
                Cow::Owned(data)
            }
        }
    }
}

// These From instances are faster than `EndpointData::new`, as they don't require deduplication.

impl From<BTreeSet<TransportAddr>> for EndpointData {
    fn from(addrs: BTreeSet<TransportAddr>) -> Self {
        Self {
            addrs: addrs.into_iter().collect(),
            user_data: None,
        }
    }
}

impl From<BTreeSet<SocketAddr>> for EndpointData {
    fn from(addrs: BTreeSet<SocketAddr>) -> Self {
        Self {
            addrs: addrs.into_iter().map(TransportAddr::Ip).collect(),
            user_data: None,
        }
    }
}

impl FromIterator<TransportAddr> for EndpointData {
    fn from_iter<T: IntoIterator<Item = TransportAddr>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

/// The function type inside [`AddrFilter`].
type AddrFilterFn =
    dyn Fn(&Vec<TransportAddr>) -> Cow<'_, Vec<TransportAddr>> + Send + Sync + 'static;

/// A filter and/or reordering function applied to transport addresses,
/// typically used by AddressLookup services in iroh before publishing.
///
/// Takes the full set of transport addresses and returns them as an ordered `Vec`,
/// allowing both filtering (by omitting addresses) and reordering (by controlling
/// the output order). A `BTreeSet` cannot preserve a custom order, so the return
/// type is `Vec` to make reordering possible.
///
/// See the documentation for each address lookup implementation for details on
/// what additional filtering the implementation may perform on top.
#[derive(Clone, Default)]
pub struct AddrFilter(Option<Arc<AddrFilterFn>>);

impl std::fmt::Debug for AddrFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_some() {
            f.debug_struct("AddrFilter").finish_non_exhaustive()
        } else {
            write!(f, "identity")
        }
    }
}

impl AddrFilter {
    /// Create a new [`AddrFilter`]
    pub fn new(
        f: impl Fn(&Vec<TransportAddr>) -> Cow<'_, Vec<TransportAddr>> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(f)))
    }

    /// Constructs a filter that doesn't filter addresses and passes all through.
    pub fn unfiltered() -> Self {
        Self::new(|addrs| Cow::Borrowed(addrs))
    }

    /// Only keep relay addresses.
    pub fn relay_only() -> Self {
        Self::new(|addrs| Cow::Owned(addrs.iter().filter(|a| a.is_relay()).cloned().collect()))
    }

    /// Only keep direct IP addresses.
    pub fn ip_only() -> Self {
        Self::new(|addrs| Cow::Owned(addrs.iter().filter(|a| !a.is_relay()).cloned().collect()))
    }

    /// Apply the address filter function to a set of addresses.
    pub fn apply<'a>(&self, addrs: &'a Vec<TransportAddr>) -> Cow<'a, Vec<TransportAddr>> {
        match &self.0 {
            Some(f) => f(addrs),
            None => Cow::Borrowed(addrs),
        }
    }
}

impl From<EndpointAddr> for EndpointData {
    fn from(endpoint_addr: EndpointAddr) -> Self {
        Self {
            // No need to check for duplicates - we already know they can't have duplicates
            addrs: endpoint_addr.addrs.into_iter().collect(),
            user_data: None,
        }
    }
}

/// User-defined data that can be published and resolved through endpoint discovery.
///
/// Under the hood this is a UTF-8 string no longer than [`UserData::MAX_LENGTH`] bytes.
///
/// Iroh does not keep track of or examine the user-defined data.
///
/// `UserData` implements [`FromStr`] and [`TryFrom<String>`], so you can
/// convert `&str` and `String` into `UserData` easily.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserData(String);

impl UserData {
    /// The max byte length allowed for user-defined data.
    ///
    /// In DNS discovery services, the user-defined data is stored in a TXT record character string,
    /// which has a max length of 255 bytes. We need to subtract the `user-data=` prefix,
    /// which leaves 245 bytes for the actual user-defined data.
    pub const MAX_LENGTH: usize = 245;
}

/// Error returned when an input value is too long for [`UserData`].
#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[error("max length exceeded")]
pub struct MaxLengthExceededError {}

impl TryFrom<String> for UserData {
    type Error = MaxLengthExceededError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ensure!(value.len() <= Self::MAX_LENGTH, MaxLengthExceededError);
        Ok(Self(value))
    }
}

impl FromStr for UserData {
    type Err = MaxLengthExceededError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        ensure!(s.len() <= Self::MAX_LENGTH, MaxLengthExceededError);
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for UserData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for UserData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Information about an endpoint that may be published to and resolved from discovery services.
///
/// This struct couples a [`EndpointId`] with its associated [`EndpointData`].
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct EndpointInfo {
    /// The [`EndpointId`] of the endpoint this is about.
    pub endpoint_id: EndpointId,
    /// The information published about the endpoint.
    pub data: EndpointData,
}

impl From<EndpointInfo> for EndpointAddr {
    fn from(value: EndpointInfo) -> Self {
        value.into_endpoint_addr()
    }
}

impl From<EndpointAddr> for EndpointInfo {
    fn from(addr: EndpointAddr) -> Self {
        Self {
            endpoint_id: addr.id,
            data: EndpointData::from(addr.addrs),
        }
    }
}

impl EndpointInfo {
    /// Creates a new [`EndpointInfo`] with an empty [`EndpointData`].
    pub fn new(endpoint_id: EndpointId) -> Self {
        Self::from_parts(endpoint_id, Default::default())
    }

    /// Creates a new [`EndpointInfo`] from its parts.
    pub fn from_parts(endpoint_id: EndpointId, data: EndpointData) -> Self {
        Self { endpoint_id, data }
    }

    /// Adds the relay URL and returns the updated endpoint info.
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.data.add_relay_url(relay_url);
        self
    }

    /// Sets the IP based addresses and returns the updated endpoint info.
    pub fn with_ip_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.data.add_ip_addrs(addrs);
        self
    }

    /// Sets the user-defined data and returns the updated endpoint info.
    pub fn with_user_data(mut self, user_data: Option<UserData>) -> Self {
        self.data.set_user_data(user_data);
        self
    }

    /// Converts into a [`EndpointAddr`] by cloning the needed fields.
    pub fn to_endpoint_addr(&self) -> EndpointAddr {
        EndpointAddr {
            id: self.endpoint_id,
            addrs: self.data.addrs.iter().cloned().collect(),
        }
    }

    /// Converts into a [`EndpointAddr`].
    pub fn into_endpoint_addr(self) -> EndpointAddr {
        let Self { endpoint_id, data } = self;
        EndpointAddr {
            id: endpoint_id,
            addrs: data.addrs.into_iter().collect(),
        }
    }

    /// Converts to TXT attributes.
    pub(crate) fn to_attrs(&self) -> TxtAttrs<IrohAttr> {
        endpoint_info_to_attrs(self)
    }

    /// Returns the transport addr information.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddr> {
        self.data.addrs()
    }

    /// Returns the relay URL of the endpoint.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.data.relay_urls()
    }

    /// Returns user data information, if set.
    pub fn user_data(&self) -> Option<&UserData> {
        self.data.user_data()
    }

    /// Returns the direct addresses of the endpoint.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.data.ip_addrs()
    }

    /// Parses a [`EndpointInfo`] from DNS TXT lookup results.
    ///
    /// The `domain_name` is the queried DNS name (e.g. `_iroh.<z32>.<origin>`).
    /// The `lookup` iterator yields TXT record values that implement [`Display`].
    pub fn from_txt_lookup(
        domain_name: String,
        lookup: impl Iterator<Item = impl Display>,
    ) -> Result<Self, ParseError> {
        let attrs: TxtAttrs<IrohAttr> =
            TxtAttrs::from_txt_lookup(domain_name, lookup, IROH_TXT_NAME)?;
        Ok(endpoint_info_from_attrs(&attrs))
    }

    /// Parses a [`EndpointInfo`] from a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self, ParseError> {
        let attrs: TxtAttrs<IrohAttr> = TxtAttrs::from_pkarr_signed_packet(packet, IROH_TXT_NAME)?;
        Ok(endpoint_info_from_attrs(&attrs))
    }

    /// Creates a [`pkarr::SignedPacket`].
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        self.to_attrs()
            .to_pkarr_signed_packet(secret_key, ttl, IROH_TXT_NAME)
    }

    /// Parses only Commons `_cmns.<z32-endpoint-id>.<origin>` TXT lookup results.
    ///
    /// This has the same trust and attribute-parsing behavior as [`Self::from_txt_lookup`].
    /// A different record label is rejected; there is no `_iroh` fallback.
    pub fn from_cmns_txt_lookup(
        domain_name: String,
        lookup: impl Iterator<Item = impl Display>,
    ) -> Result<Self, ParseError> {
        let attrs: TxtAttrs<IrohAttr> =
            TxtAttrs::from_txt_lookup(domain_name, lookup, CMNS_TXT_NAME)?;
        Ok(endpoint_info_from_attrs(&attrs))
    }

    /// Parses only the `_cmns` records under a native packet's signer zone.
    ///
    /// No matching records yields empty endpoint data, just as for the native `_iroh`
    /// parser. Invalid address values are discarded. Callers decide whether the result
    /// is usable and own chain authority, freshness and replay policy.
    ///
    /// This method does not verify the packet signature. For untrusted bytes, use
    /// [`pkarr::SignedPacket::from_bytes`] first; unchecked packet constructors do not
    /// establish authenticity. Parsing leaves the signed packet unchanged.
    pub fn from_cmns_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self, ParseError> {
        let attrs: TxtAttrs<IrohAttr> = TxtAttrs::from_pkarr_signed_packet(packet, CMNS_TXT_NAME)?;
        Ok(endpoint_info_from_attrs(&attrs))
    }

    /// Creates a new native signed packet containing only `_cmns` endpoint records.
    ///
    /// Encoding uses the supplied key's identity and a fresh native timestamp, with
    /// the supplied TTL. As in [`Self::to_pkarr_signed_packet`], `self.endpoint_id` is
    /// not checked against that key. This is not byte-preserving packet forwarding;
    /// forward original packet bytes when preserving an existing signature and age.
    pub fn to_cmns_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        self.to_attrs()
            .to_pkarr_signed_packet(secret_key, ttl, CMNS_TXT_NAME)
    }

    /// Converts into a list of `{key}={value}` strings.
    pub fn to_txt_strings(&self) -> Vec<String> {
        self.to_attrs().to_txt_strings().collect()
    }
}

/// Convert [`EndpointInfo`] to [`TxtAttrs`].
fn endpoint_info_to_attrs(info: &EndpointInfo) -> TxtAttrs<IrohAttr> {
    let mut attrs = vec![];
    for addr in &info.data.addrs {
        match addr {
            TransportAddr::Relay(url) => attrs.push((IrohAttr::Relay, url.to_string())),
            TransportAddr::Ip(addr) => attrs.push((IrohAttr::Addr, addr.to_string())),
            TransportAddr::Custom(addr) => attrs.push((IrohAttr::Addr, addr.to_string())),
            _ => {}
        }
    }

    if let Some(user_data) = &info.data.user_data {
        attrs.push((IrohAttr::UserData, user_data.to_string()));
    }
    TxtAttrs::from_parts(info.endpoint_id, attrs.into_iter())
}

/// Parse [`EndpointInfo`] from [`TxtAttrs`].
fn endpoint_info_from_attrs(attrs: &TxtAttrs<IrohAttr>) -> EndpointInfo {
    use iroh_base::CustomAddr;

    let endpoint_id = attrs.endpoint_id();
    let a = attrs.attrs();
    let relay_urls = a
        .get(&IrohAttr::Relay)
        .into_iter()
        .flatten()
        .filter_map(|s| Url::parse(s).ok())
        .map(|url| TransportAddr::Relay(url.into()));
    let addrs = a
        .get(&IrohAttr::Addr)
        .into_iter()
        .flatten()
        .filter_map(|s| {
            if let Ok(addr) = SocketAddr::from_str(s) {
                Some(TransportAddr::Ip(addr))
            } else if let Ok(addr) = CustomAddr::from_str(s) {
                Some(TransportAddr::Custom(addr))
            } else {
                None
            }
        });

    let user_data = a
        .get(&IrohAttr::UserData)
        .into_iter()
        .flatten()
        .next()
        .and_then(|s| UserData::from_str(s).ok());
    let mut data = EndpointData::default();
    data.set_user_data(user_data);
    data.add_addrs(relay_urls.chain(addrs));

    EndpointInfo { endpoint_id, data }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use iroh_base::{EndpointId, SecretKey, TransportAddr};
    use n0_error::Result;

    use super::{EndpointData, EndpointInfo};
    use crate::dns::TxtRecordData;

    #[test]
    fn txt_attr_roundtrip() {
        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
        ])
        .with_user_data("foobar".parse().unwrap());
        let endpoint_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = EndpointInfo::from_parts(endpoint_id, endpoint_data);
        let attrs = expected.to_attrs();
        let actual = super::endpoint_info_from_attrs(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip() {
        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();
        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
        ])
        .with_user_data("foobar".parse().unwrap());
        let expected = EndpointInfo::from_parts(secret_key.public(), endpoint_data);
        let packet = expected.to_pkarr_signed_packet(&secret_key, 30).unwrap();
        let actual = EndpointInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn txt_attr_roundtrip_with_custom_addr() {
        use iroh_base::CustomAddr;

        let bt_addr = CustomAddr::from_parts(1, &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        let tor_addr = CustomAddr::from_parts(42, &[0xab; 32]);

        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
            TransportAddr::Custom(bt_addr),
            TransportAddr::Custom(tor_addr),
        ]);
        let endpoint_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = EndpointInfo::from_parts(endpoint_id, endpoint_data);
        let attrs = expected.to_attrs();
        let actual = super::endpoint_info_from_attrs(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip_with_custom_addr() {
        use iroh_base::CustomAddr;

        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();

        let bt_addr = CustomAddr::from_parts(1, &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        let tor_addr = CustomAddr::from_parts(42, &[0xab; 32]);

        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
            TransportAddr::Custom(bt_addr),
            TransportAddr::Custom(tor_addr),
        ])
        .with_user_data("foobar".parse().unwrap());

        let expected = EndpointInfo::from_parts(secret_key.public(), endpoint_data);
        let packet = expected.to_pkarr_signed_packet(&secret_key, 30).unwrap();
        let actual = EndpointInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(expected, actual);
    }

    /// There used to be a bug where uploading an EndpointAddr with more than only exactly
    /// one relay URL or one publicly reachable IP addr would prevent connection
    /// establishment.
    ///
    /// The reason was that only the first address was parsed (e.g. 192.168.96.145 in
    /// this example), which could be a local, unreachable address.
    #[test]
    fn test_from_txt_lookup() -> Result {
        let name = "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.";
        let records = vec![
            TxtRecordData::from(vec!["addr=192.168.96.145:60165".to_string()]),
            TxtRecordData::from(vec!["addr=213.208.157.87:60165".to_string()]),
            TxtRecordData::from(vec![
                "relay=https://euw1-1.relay.iroh.network./".to_string(),
            ]),
        ];
        let endpoint_info = EndpointInfo::from_txt_lookup(name.to_string(), records.into_iter())?;

        let expected_endpoint_info = EndpointInfo::new(EndpointId::from_str(
            "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18",
        )?)
        .with_relay_url("https://euw1-1.relay.iroh.network./".parse()?)
        .with_ip_addrs(vec![
            "192.168.96.145:60165".parse().unwrap(),
            "213.208.157.87:60165".parse().unwrap(),
        ]);

        assert_eq!(endpoint_info, expected_endpoint_info);

        Ok(())
    }
}

#[cfg(test)]
mod cmns_tests {
    use iroh_base::{CustomAddr, SecretKey, TransportAddr};
    use simple_dns::{CLASS, Name, Packet, ResourceRecord, rdata::RData};

    use super::{EndpointData, EndpointInfo};
    use crate::{
        CMNS_TXT_NAME, IROH_TXT_NAME,
        pkarr::{SignedPacket, Timestamp},
    };

    fn mixed_packet(key: &SecretKey, records: &[(String, &str)]) -> SignedPacket {
        let mut packet = Packet::new_reply(0);
        for (name, value) in records {
            packet.answers.push(ResourceRecord::new(
                Name::new(name).unwrap().into_owned(),
                CLASS::IN,
                30,
                RData::TXT((*value).try_into().unwrap()),
            ));
        }
        let encoded = packet.build_bytes_vec_compressed().unwrap();
        let timestamp = Timestamp::from_micros(1_720_000_000_000_000);
        let mut signable =
            format!("3:seqi{}e1:v{}:", timestamp.as_micros(), encoded.len()).into_bytes();
        signable.extend_from_slice(&encoded);
        let packet = SignedPacket::from_parts_unchecked(
            key.public().as_bytes(),
            &key.sign(&signable).to_bytes(),
            timestamp,
            &encoded,
        )
        .unwrap();
        SignedPacket::from_bytes(packet.as_bytes()).unwrap()
    }

    #[test]
    fn cmns_roundtrip_preserves_native_data_and_packet_verification() {
        let key = SecretKey::from_bytes(&[1; 32]);
        let data = EndpointData::from_iter([
            TransportAddr::Relay("https://relay.example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
            TransportAddr::Custom(CustomAddr::from_parts(42, &[3; 16])),
        ])
        .with_user_data("commons endpoint".parse().unwrap());
        let expected = EndpointInfo::from_parts(key.public(), data);
        let packet = expected.to_cmns_pkarr_signed_packet(&key, 47).unwrap();
        let bytes = packet.as_bytes().to_vec();
        let timestamp = packet.timestamp();
        let verified = SignedPacket::from_bytes(&bytes).unwrap();
        assert_eq!(
            EndpointInfo::from_cmns_pkarr_signed_packet(&verified).unwrap(),
            expected
        );
        assert_eq!(verified.public_key(), key.public());
        assert_eq!(verified.timestamp(), timestamp);
        assert_eq!(verified.as_bytes(), bytes);
        let native = Packet::parse(verified.encoded_packet()).unwrap();
        assert!(!native.answers.is_empty());
        assert!(native.answers.iter().all(|record| record.ttl == 47
            && record.name.to_string() == format!("_cmns.{}", key.public().to_z32())));
        assert!(
            !EndpointInfo::from_pkarr_signed_packet(&verified)
                .unwrap()
                .data
                .has_addrs()
        );
        let old = expected.to_pkarr_signed_packet(&key, 47).unwrap();
        assert_eq!(
            old.txt_records(IROH_TXT_NAME),
            verified.txt_records(CMNS_TXT_NAME)
        );
        assert_eq!(
            EndpointInfo::from_pkarr_signed_packet(&old).unwrap(),
            expected
        );
        assert!(
            !EndpointInfo::from_cmns_pkarr_signed_packet(&old)
                .unwrap()
                .data
                .has_addrs()
        );
        let mut tampered = bytes;
        tampered[104] ^= 1;
        assert!(SignedPacket::from_bytes(&tampered).is_err());
    }

    #[test]
    fn mixed_namespaces_are_selected_before_attribute_parsing() {
        let key = SecretKey::from_bytes(&[1; 32]);
        let origin = key.public().to_z32();
        let foreign = SecretKey::from_bytes(&[2; 32]).public().to_z32();
        let packet = mixed_packet(
            &key,
            &[
                (format!("_iroh.{origin}"), "addr=127.0.0.1:1001"),
                (format!("_cmns.{origin}"), "addr=127.0.0.1:1002"),
                (format!("_cmns-other.{origin}"), "malformed"),
                (format!("_cmns.child.{origin}"), "malformed"),
                (format!("_cmns.{foreign}"), "malformed"),
            ],
        );
        let before = packet.as_bytes().to_vec();
        assert_eq!(
            EndpointInfo::from_pkarr_signed_packet(&packet)
                .unwrap()
                .ip_addrs()
                .collect::<Vec<_>>(),
            vec!["127.0.0.1:1001".parse().unwrap()]
        );
        assert_eq!(
            EndpointInfo::from_cmns_pkarr_signed_packet(&packet)
                .unwrap()
                .ip_addrs()
                .collect::<Vec<_>>(),
            vec!["127.0.0.1:1002".parse().unwrap()]
        );
        assert_eq!(packet.as_bytes(), before);
        for (valid, invalid) in [
            (IROH_TXT_NAME, CMNS_TXT_NAME),
            (CMNS_TXT_NAME, IROH_TXT_NAME),
        ] {
            let packet = mixed_packet(
                &key,
                &[
                    (format!("{valid}.{origin}"), "addr=127.0.0.1:1003"),
                    (format!("{invalid}.{origin}"), "malformed"),
                ],
            );
            let (selected, other) = if valid == IROH_TXT_NAME {
                (
                    EndpointInfo::from_pkarr_signed_packet(&packet),
                    EndpointInfo::from_cmns_pkarr_signed_packet(&packet),
                )
            } else {
                (
                    EndpointInfo::from_cmns_pkarr_signed_packet(&packet),
                    EndpointInfo::from_pkarr_signed_packet(&packet),
                )
            };
            assert_eq!(
                selected.unwrap().ip_addrs().collect::<Vec<_>>(),
                vec!["127.0.0.1:1003".parse().unwrap()]
            );
            assert!(other.is_err());
        }
    }

    #[test]
    fn both_namespaces_keep_native_missing_malformed_and_txt_label_behavior() {
        let key = SecretKey::from_bytes(&[1; 32]);
        for label in [IROH_TXT_NAME, CMNS_TXT_NAME] {
            let parse = |packet: &SignedPacket| {
                if label == IROH_TXT_NAME {
                    EndpointInfo::from_pkarr_signed_packet(packet)
                } else {
                    EndpointInfo::from_cmns_pkarr_signed_packet(packet)
                }
            };
            for value in ["malformed", "unknown=value"] {
                let packet = SignedPacket::from_txt_strings(&key, label, [value], 30).unwrap();
                assert!(parse(&packet).is_err());
            }
            let invalid_addr =
                SignedPacket::from_txt_strings(&key, label, ["addr=invalid"], 30).unwrap();
            assert!(!parse(&invalid_addr).unwrap().data.has_addrs());
            let absent = SignedPacket::from_txt_strings(&key, "_other", ["malformed"], 30).unwrap();
            assert_eq!(parse(&absent).unwrap(), EndpointInfo::new(key.public()));
            for actual_label in [IROH_TXT_NAME, CMNS_TXT_NAME, "_cmns-other"] {
                let name = format!("{actual_label}.{}.example.com", key.public().to_z32());
                let records = ["addr=127.0.0.1:2001"].into_iter();
                let result = if label == IROH_TXT_NAME {
                    EndpointInfo::from_txt_lookup(name, records)
                } else {
                    EndpointInfo::from_cmns_txt_lookup(name, records)
                };
                if actual_label == label {
                    assert_eq!(
                        result.unwrap().ip_addrs().collect::<Vec<_>>(),
                        vec!["127.0.0.1:2001".parse().unwrap()]
                    );
                } else {
                    let error = result.unwrap_err();
                    if label == IROH_TXT_NAME {
                        assert!(
                            error
                                .to_string()
                                .contains("Record is not an `iroh` record, expected `_iroh`")
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn encoding_keeps_native_signer_identity_behavior() {
        let key = SecretKey::from_bytes(&[1; 32]);
        let other = SecretKey::from_bytes(&[2; 32]);
        let info = EndpointInfo::new(other.public())
            .with_ip_addrs(vec!["127.0.0.1:3001".parse().unwrap()]);
        let old = info.to_pkarr_signed_packet(&key, 30).unwrap();
        let cmns = info.to_cmns_pkarr_signed_packet(&key, 30).unwrap();
        let old = EndpointInfo::from_pkarr_signed_packet(&old).unwrap();
        let cmns = EndpointInfo::from_cmns_pkarr_signed_packet(&cmns).unwrap();
        assert_eq!(cmns, old);
        assert_eq!(cmns.endpoint_id, key.public());
        assert_ne!(cmns.endpoint_id, info.endpoint_id);
        assert_eq!(cmns.data, info.data);
    }
}
