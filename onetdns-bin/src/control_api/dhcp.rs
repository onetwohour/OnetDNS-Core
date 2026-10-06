/*!
 * @brief 관리 API: DHCP 임대와 고정 할당.
 */

use super::*;
use crate::edge::{
    apply_lease_sync, apply_static_add, apply_static_remove, leases_json, static_reservations_json,
};

impl ControlDeps {
    /** @brief 지금 나가 있는 DHCPv4·DHCPv6 임대. */
    pub(super) fn dhcp_leases(&self) -> String {
        let v4 = self.dhcp_slot.lock_recover().clone();
        let v6 = self.dhcp6_slot.lock_recover().clone();
        leases_json(v4.as_ref(), v6.as_ref(), &self.vendor_db.load())
    }

    /** @brief 다른 서버에서 온 임대를 받아들인다. */
    pub(super) fn dhcp_lease_put(&self, body: &str) -> Result<String, String> {
        match self.dhcp_slot.lock_recover().clone() {
            Some(pool) => apply_lease_sync(&pool, body),
            None => Err("DHCPv4 is not configured".to_string()),
        }
    }

    /** @brief DHCP 고정 할당 목록. */
    pub(super) fn dhcp_static_list(&self) -> String {
        static_reservations_json(self.dhcp_slot.lock_recover().as_ref())
    }

    /** @brief DHCP 고정 할당을 넣는다. */
    pub(super) fn dhcp_static_add(&self, body: &str) -> Result<String, String> {
        match self.dhcp_slot.lock_recover().clone() {
            Some(pool) => apply_static_add(&pool, body),
            None => Err("DHCPv4 is not configured".to_string()),
        }
    }

    /** @brief DHCP 고정 할당을 뺀다. */
    pub(super) fn dhcp_static_remove(&self, identity: &str) -> Result<String, String> {
        match self.dhcp_slot.lock_recover().clone() {
            Some(pool) => apply_static_remove(&pool, identity),
            None => Err("DHCPv4 is not configured".to_string()),
        }
    }
}
